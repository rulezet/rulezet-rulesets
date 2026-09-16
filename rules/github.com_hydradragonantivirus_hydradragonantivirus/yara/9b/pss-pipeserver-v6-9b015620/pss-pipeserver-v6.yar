rule PSS_Pipeserver_v6 {
  meta:
    description = "PSS Pipeserver version 6.0.0 and 6.1.0"
    author      = "Geoffrey Alexander <geoff@citizenlab.ca>"
    date        = "2017-07-20"

  strings:
    $p1 = "PSS_Agent" ascii
    $p2 = "pss-agent" ascii

    $s1 = "%2s%u.%u.%u.%u\\\\n" wide
    $s2 = "CustomerConfigException@agent" ascii

    $str_decrypt_loop = { 8b 47 04 8b ce 83 e1 03 c1 e1 03 ba ?? ?? ?? ?? d3 ea 32 54 35 ?? 88 14 06 46 3b f3 }

  condition:
    uint16(0) == 0x5a4d and $str_decrypt_loop and 1 of ($p*) and 1 of ($s*)
}