rule _Virus_Hijack_Gen_Trojan_ShellObject_i8Y_aSl2g6j_9_2_Virus_Hijac_140 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aSl2g6j_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aCkwazk_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_15_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8W@aKuHmDp_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.l8Z@aKTibuk_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.m0Z@ae3yXvm_30_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.MuZ@amBwvTb_26_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.myZ@aOWVavp_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0155ee1fddf4b66e2952d582da4c762953a62c807ba549a87ae1c07fc820f03"
    hash2       = "7a9f18912c7e767a058b8f5fecefa05b13579a1ba5b75706ffc702e92f6cd614"
    hash3       = "1d349aedd4c637399e31180fdf85a358ca691b8d450dd1ad339ca74ea939eea2"
    hash4       = "7675e664ca1e9b3ebf3a7b2e3d1433ad4b7a66c34cc8ef17ca865ea19b36d48e"
    hash5       = "30b223ce803ec0ed8ae732f7eb2d644b2525d139a82a88206bba1ae65b3644b9"
    hash6       = "83c0ba0f8d82400f0d8404f3692c1cf40e621a56053df913b37a201e4e2c3082"
    hash7       = "a3a1d912f3b2537fdad282923170ea86df36a9c853fa674b9ed4f05882701736"
    hash8       = "24d19ef1d07bc82d47ef275b0a510b037eb886f2a780894325c766915dcff7dc"
    hash9       = "9d935d162a2711eff9d2d5f626129a9cda42cb353a413962877bf44d8911a6a6"
    hash10      = "0e3736795b0e2413ac80aed13fddd53def80d3a96a2d5fc1a002521e1bc58d44"

  strings:
    $x1  = "%ls\\conhost.exe --headless --width %d --height %d --signal 0x%x -- %ls" fullword wide
    $s2  = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\" xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\"><t" ascii
    $s3  = "%s - failed to execute %ls, error:%d" fullword ascii
    $s4  = "LsaRegisterLogonProcess failed, error:%x" fullword ascii
    $s5  = "%s: LsaLogonUser() failed: User '%s' Status: %08X SubStatus %d." fullword ascii
    $s6  = "failed to convert utf8 payload:%s error:%d" fullword ascii
    $s7  = "lseek - ERROR, origin is not supported %d" fullword ascii
    $s8  = "send - ERROR: flags are not currently supported, io:%p" fullword ascii
    $s9  = "%s - unable to generate identity token for %s from custom lsa provider: %s" fullword ascii
    $s10 = "recv - ERROR: flags are not currently supported, io:%p" fullword ascii
    $s11 = "GetSystemDirectory failed with error %d" fullword ascii
    $s12 = "%s - DuplicateToken failed with %d" fullword ascii
    $s13 = "GetConsoleMode on hOutputConsole failed with %d" fullword ascii
    $s14 = "GetStdHandle on OutputHandle failed with %d" fullword ascii
    $s15 = "unable to retrieve system32 path" fullword ascii
    $s16 = "chroot only supports absolute paths" fullword ascii
    $s17 = "LSA auth request is successful for user:%s " fullword ascii
    $s18 = "LSA auth request, user:%s lsa_pkg:%s " fullword ascii
    $s19 = "LsaLookupAuthenticationPackage failed, lsa auth pkg:%ls error:%x" fullword ascii
    $s20 = "console supports the ansi parsing" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}