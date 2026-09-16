rule _Trojan_Hooker_Win32_Floxif_A_33_1_Virus_Autorun_Generic_Dacic_3_544 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_33_1.vir, Virus.Autorun_Generic.Dacic.3DD73544.A.1D459A1C.vir, Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_20.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_12_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_10_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8W@auCCoZb_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9594b207d3fab009a7900e1031007d8e8122ad0b57956c9b000b53dcc487e7a"
    hash2       = "f1199c465067c2d9fa2a32a8dd6296a1b3c9af40ac3cfb37fc3b32b2bd13be19"
    hash3       = "0255cd2cf4f9600aa284e4fffc627641429d2d38e5fa1ac5b1a34dbc099ad2cc"
    hash4       = "022bc1efd735f0b891ae6eb5df74939e368e6b129e799f53c37d4d63b3a08efb"
    hash5       = "b195194f85cd52d826bc334f0021646b6503a7a26a2d1b58db02f130676aa40e"
    hash6       = "ebf10e649fe855c0c01c95d4e134f4202e53c5f2db2c2eba4e165939a346ea7d"
    hash7       = "97121aeedf128abc5ad8715f79d3696d32348a8c453f7e1415a75f72b756049d"
    hash8       = "f91e29b13b06cd530269c794e52d77cc838fa87a0cd6c6d81cb492f8f246468b"
    hash9       = "5d9804ff2d27070141d1d4026f463726ee4df82e182a45804922613d9e80c7d3"
    hash10      = "19cbcc29628d4c642c52ee515e5c0cadbee9dbc08e29cd2abf9ce25ab121a57b"
    hash11      = "c2816a5380456292f9574b067d7b3197da5210eadcc6b2977fcf8b8eac5fd135"
    hash12      = "293cc6207e0313f3e6e3e9fce113d6f7a2f721942b9fab96da2318d55bc5d66e"

  strings:
    $s1 = "<INSERT>" fullword ascii
    $s2 = "<LEFT>" fullword ascii
    $s3 = "<SHIFT>" fullword ascii
    $s4 = "<RIGHT>" fullword ascii
    $s5 = "<PRINT>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}