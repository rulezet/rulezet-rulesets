rule metasploit_download_exec_shellcode_rev2 {
    meta:
        author = "FDD @ Cuckoo Sandbox"
        description = "Rule for metasploit's download and exec shellcode"
        name = "Metasploit download & exec payload"
        URL = 185

    strings:
        $s1 = { fce8 8?00 0000 60 }             $s2 = { 648b ??30 }                     $s4 = { 4c77 2607 }                     $s5 = { 3a56 79a7 }                     $s6 = { 5789 9fc6 }                     $s7 = { eb55 2e3b }                     $s9 = { 2d06 187b }                     $url = /\/[\w_\-\.]+/

    condition:
        all of them and filesize < 5KB
}