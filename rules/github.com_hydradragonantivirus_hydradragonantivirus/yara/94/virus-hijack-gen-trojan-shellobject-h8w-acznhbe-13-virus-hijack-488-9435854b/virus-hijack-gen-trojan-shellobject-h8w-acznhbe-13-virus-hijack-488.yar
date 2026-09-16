rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_aCZnhbe_13_Virus_Hijack_488 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_13.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_4_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0bd40b3a112ccb5a6575ab4c3b2d125a76a49ad9accb8d6c1a6a4aac64389cb"
    hash2       = "8ffc22831e7cc7f8347786df680a1e88334870291eaba78062c7ed10ea78b48b"
    hash3       = "5336a38be33b2f8f6afba2ca60483c7b17e16565f5b073d2e712f96a104c626e"
    hash4       = "cffbafc868dadaa45420c56b5aa9a98fd0867cd2712ea4d03d71bf4f4eba74f6"
    hash5       = "fc08f422e4679b557dcc2c34468c4ef2df0ad33aa3b96e249cf098fae94167ff"
    hash6       = "22fa522d7bb7644a76f58332a41943de55772ce9aeb4935923362498816bfc91"

  strings:
    $s1  = "liblzma example programs" fullword ascii
    $s2  = "    to binary mode. On systems where it matters (e.g. Windows) it is" fullword ascii
    $s3  = "    On POSIX systems, the examples should build by just typing \"make\"." fullword ascii
    $s4  = "                                        a compression preset" fullword ascii
    $s5  = "                                        compression using a compression" fullword ascii
    $s6  = "List of examples" fullword ascii
    $s7  = "    The examples that use stdin or stdout don't set stdin and stdout" fullword ascii
    $s8  = "    The examples are written so that the same comments aren't" fullword ascii
    $s9  = "    03_compress_custom.c                Like 01_compress_easy.c but using" fullword ascii
    $s10 = "                                        a custom filter chain" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}