rule _Virus_Hijack_Gen_Trojan_ShellObject_h8W_a853Pwn_8_2_Virus_Hijac_479 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.h8W@a853Pwn_8_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aCZnhbe_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@aqG68Ic_8.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_2_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a853Pwn_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eceeb6efc1d2c73f0ac2df33735d55f7b3a6a02784dd4b94c20b618fe6352bf3"
    hash2       = "af122a43566658c59431579a38ca42e1c1130cf060ad6913caab603a165b5529"
    hash3       = "64d877c8985bce6cf68247548555db3628547393c883e98cbb4c7262c904aa24"
    hash4       = "96703675d1d85d71d9471c2f407b3dce01ee6eaece009751c37f3e89bf96c723"
    hash5       = "7302e964793f853740b92325b2308b5537a880881a4acd99e6cb5ffbddc300ae"
    hash6       = "6ae945d9454e7c28385aa815b66e1fb51ef97fe11478e18426b316f45d20a3d6"
    hash7       = "25580ea287f391443b3f34e0d22069b5b1739b6312c794f7f97a82c0c4488470"
    hash8       = "c3788feb3a3c0bae28b2195ac8a2455c7c77672b87ae9edd4bfb90f434994ebc"
    hash9       = "f4a9cd428b07c5fba4e6b4e2a99a6c74140c9c66d8c7c1b1c8e4a9bed16ac6a1"
    hash10      = "62a14b7a4498548b834b6e8b9fd51580efdfe695a3db8601a32229e4325a0732"

  strings:
    $s1  = "for target in $@ ; do" fullword ascii
    $s2  = "trap \"rm -f $PEM1 $PEM2\" SIGINT" fullword ascii
    $s3  = "echo root@localhost.localdomain" fullword ascii
    $s4  = "cat $PEM1 >  ${target}" fullword ascii
    $s5  = "cat $PEM2 >> ${target}" fullword ascii
    $s6  = "echo \"\"   >> ${target}" fullword ascii
    $s7  = "echo localhost.localdomain" fullword ascii
    $s8  = "echo --" fullword ascii
    $s9  = "if [ $# -eq 0 ] ; then" fullword ascii
    $s10 = "echo SomeCity" fullword ascii
    $s11 = "echo SomeOrganization" fullword ascii
    $s12 = "echo SomeState" fullword ascii
    $s13 = "echo $\"Usage: `basename $0` filename [...]\"" fullword ascii
    $s14 = "echo SomeOrganizationalUnit" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}