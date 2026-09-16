import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_115_1_Tro_485 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_115_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_178_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_258_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_303_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_343_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_375_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_398_1.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_577_1.vir, Virus.Danger_Gen.Trojan.ShellObject.f8Y@aiYvnz.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_5.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_6.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_7.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_8.vir, Virus.Hijack_Trojan.GenericKDZ.98388_122.vir, Virus.Hijack_Trojan.GenericKDZ.98388_123.vir, Virus.Hijack_Trojan.GenericKDZ.98388_155.vir, Virus.Hijack_Trojan.GenericKDZ.98388_213.vir, Virus.Hijack_Trojan.GenericKDZ.98388_25.vir, Virus.Hijack_Trojan.GenericKDZ.98388_69.vir, Virus.Hijack_Trojan.GenericKDZ.98388_89.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63468e208a9d4c594e3013dcc581d6d944b80d059580df68330ee15182bbfec2"
    hash2       = "0729e5d25f6fab3cda825e4e7de6419d57403af41877adecc2431e1b75e4ba63"
    hash3       = "bd46c23a7e14666c22b9269c6c74fb76ae476cbeac12b1680cdab82018f3b67b"
    hash4       = "9014ab1159cde4b0e229d57861474ba69786d0302aefae600b233f1be71b636d"
    hash5       = "162cf8e2191f0ec20f48293038437d1939eb3e5e877cfc0aaa0b3515df825203"
    hash6       = "f234c048d1c849eba30a38bb9183a951db024fbcafaac280880bbc7081c9e612"
    hash7       = "fcf944a5704652fde8ec46bdba0df6163b8008e714b09054a68f652d8ef05318"
    hash8       = "f2d330df797834276df3bad78af2711cec2fbe37e6c6ea870e7f922cf47fa8f2"
    hash9       = "bd2355d272d6d6327acdb235540bc116073a2f260446301cd1798be56a923010"
    hash10      = "cc0ca44d093d6d7f43671ed67780c06f47a0cbb5fbb3a8ecd7be13c36dc5e490"
    hash11      = "a51f46672f1fe36648aeeb22cc8d0113eeca0fa36226b4bf715e1ba58126f1c1"
    hash12      = "303ae77252e09ce2a2187fb26bb0c813597e61689da959994dfa9b41fa4a83d3"
    hash13      = "3c86109c6ceb91b40c4aa43b19943b35fe3fd3576f99691deb7de0b3c78dccd1"
    hash14      = "45dc8ffdbe404f86d9af004aa1201e1bffa14413928441ea8a8ba757bfede2dd"
    hash15      = "7c1e84cc35b77129949533d42ec380486aa62436bf5c74e717f7064fd332e5e8"
    hash16      = "88929c9e3defdd0a96776409952f849627240dfbaccc6ec336111754cefed0b1"
    hash17      = "d63c3efb4a14bd5283954390aa3a21e1eabed110399cfd7e9ed77e7d218321db"
    hash18      = "93b2f038a72af0f8f820a925b65df28b90ff3068d54e66d98a1a5273fc6e6f72"
    hash19      = "66e5cff8ec7b7a42845fe56e3acbafb79b73ca30cc2a4bfeaf383a2b74aab798"
    hash20      = "c8db7d0d2fff1a7036dbea8ff3e37ae81210f12bae929897d1f91fd0c571814d"
    hash21      = "309a86eb34dab4e4ca3273083d0e992032c280971a792f69ad91c1d6c088d4bc"
    hash22      = "0014706183d353845cfd4bac16648f4cfa22b09bff7710921e40068cef46e44a"
    hash23      = "a191f3841dd9056fa9b4a7bd30e2ba5bb715fa1086e52d0845c1fff025771e7b"
    hash24      = "60183828ad1bd74935b31bd267dcc1fec48e7609bb131027de84d3dd098fa2da"
    hash25      = "672a55fcc7d7efda13f311600724bc77722b5383409006a410d2ad767b62dab8"

  strings:
    $s1  = "mwww.oracle.com/education/oln/index.html, and may be updated by Oracle from time to time without notice to you. You" fullword ascii
    $s2  = "Australian Consumer Law. You are entitled to a replacement or refund for a major failureice 2013. This is a license agreement" fullword ascii
    $s3  = "Named User Plus: is defined as an individual authorized by you to use the programs which are installed on a single server orulat" ascii
    $s4  = "Named User Plus: is defined as an individual authorized by you to use the programs which are installed on a single server orulat" ascii
    $s5  = "return the software or computer for a refund or credit under that policy. " fullword ascii
    $s6  = "installed copy of the soft3. Small Claims Court. You may also litigate any dispute in small claims court in your county of" fullword ascii
    $s7  = "installed copy of the soft" fullword ascii
    $s8  = "ions apply to the" fullword ascii
    $s9  = "pon the TRMs. Oracle shall retain all title, copyright and other proprietary rights in" fullword ascii
    $s10 = "tle, copyright and other proprietary rights in" fullword ascii
    $s11 = "n, you will receive reminders to obtain a" fullword ascii
    $s12 = "purposes, and use that backup copy as described" fullword ascii
    $s13 = "markings placed upon the TRMs. Oracle shall retain all title, copyright and other proprietary rights in" fullword ascii
    $s14 = " the TRMs. Oracle shall retain all title, copyright and other proprietary rights in" fullword ascii
    $s15 = " a single copy of the software for backup purposes, and use that backup copy as described" fullword ascii
    $s16 = "Oracle programs.lations of the United States and any other relevant local export laws and regulations apply to the" fullword ascii
    $s17 = "Learning Credits: may be used to acquire education produc" fullword ascii
    $s18 = "installed copy of the softthese features can be switched off or you can choose not to use them." fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "8bc88903e0efb64dfaf2ef4a7fa39676" and (8 of them)
    ) or (all of them)
}