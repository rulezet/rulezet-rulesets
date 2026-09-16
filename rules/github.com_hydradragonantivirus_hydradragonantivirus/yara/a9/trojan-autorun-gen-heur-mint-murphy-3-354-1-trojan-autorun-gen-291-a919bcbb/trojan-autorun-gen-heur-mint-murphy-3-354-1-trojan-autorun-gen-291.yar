import "pe"
rule _Trojan_Autorun_Gen_Heur_Mint_Murphy_3_354_1_Trojan_Autorun_Gen__291 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Murphy.3_354_1.vir, Trojan.Autorun_Gen.Heur.Mint.Murphy.3_355_1.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.emZbaKq9kbjb_1_1.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.emZbaKq9kbjb_2.vir, Trojan.Autorun_Gen.Variant.Barys.429254_1.vir, Trojan.Autorun_Gen.Variant.Barys.437187_3.vir, Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_6_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_52_1.vir, Trojan.Autorun_Trojan.GenericKD.72254740_7_1.vir, Trojan.Autorun_Trojan.GenericKD.72517131_4_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_3.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_4.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_3.vir, Virus.Hijack_Trojan.GenericKDZ.98113_231.vir, Virus.Hijack_Trojan.GenericKDZ.98113_395.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52f8b2b38436806e4744bb7e75d5b0cb524b9f866bb19ec11f990a38b184115d"
    hash2       = "315f494c77fd7708a4aff2b2d669b6fb879f58daed8bde82dcf7303a3f72ba96"
    hash3       = "dbeb09a59443b362612de1e947b3b1968e9e080fe31084c26e05dbacddbededa"
    hash4       = "eceb1e80be154d8524ec3a46f16c36a36e4a9de7706e1350e6677635fd9f511a"
    hash5       = "3f8ebb347d64794aa0a2c1290844e2f3c918f40dbd20ed61761bacc60e28770d"
    hash6       = "f70e69ef61b0e5431f52e1328b204d80cae1de6dd48998ee5d577679c115ccd1"
    hash7       = "60090fe0c3d15ebf759730eda41e5f7e950d49f853e5d03b5af2f84b4d2ead3a"
    hash8       = "a61909ad8e2972f8601f67ac631e80708a1c1ce2f9c1e30f0138e4564bee3953"
    hash9       = "b50ba17ca710b145300d6a56c5bed238b8c092c64c0bafd0a4fdd183c6b81c0f"
    hash10      = "a1459be772d29cc2990280328793059d0117a46374d5916b7eec64b475c0c9b3"
    hash11      = "f4e056f2f6248b7a3ef8fd7a17e6503900bc24cce4ee9c6dc4b54537fd25b8af"
    hash12      = "de13a994dafc267b3fbf2cb21cfd962bcf1eba016611bca66d758c1d2bb2c0ad"
    hash13      = "170ddf9cb69bf05a1b47e02e12b6bf82a72cca07f9bef2e4fec17b6807b30400"
    hash14      = "2dbc6458dc0b4ad6a1e14067d5c4b78bbbca02a136810a71c13974a2de27efd5"
    hash15      = "f53221edcce5bf23ff9d58a9f01db964003a81ca79d757c199e0f0287f863166"
    hash16      = "02f6a6945e43a7ce125f58d5a5cc9f963901d047b756796f8bb253e002bf54b1"
    hash17      = "152d061df922ddc5b1bc134459df5698e07f3c5ec5e62ee1f91342e00a1a411b"
    hash18      = "942464790516fbdd7af808c256d97edfe42b8aeaea61517b3ddbd38a9af4a824"
    hash19      = "ad4784bb1a31d0dd933a0bd734a83541112b798fb4a0d94175676ab68c37c45e"
    hash20      = "276da7b40869d1178c13973e3cbadd124bc1f514e9e99e3995c678387f1276ff"
    hash21      = "549cf2d794ffdb3230c8f12d3f385cff5dc362f3e6ec7ae49b275175601e8c48"

  strings:
    $s1  = "System.Private.TypeLoader.dll                          : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s2  = "System.Private.PortableServiceModelThunks.dll          : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s3  = "System.Private.PortableThunks.dll                      : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s4  = "System.Private.DeveloperExperience.AppX.dll            : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s5  = "System.Private.CoreLib.dll                             : 4.6.25601.00 built by: DDBLD366D-dlab" fullword ascii
    $s6  = "System.Private.WinRTInterop.CoreLib.dll                : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s7  = "System.Private.Interop.dll                             : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s8  = "System.Private.CompatQuirks.dll                        : 4.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s9  = "nutc_driver.exe : 1.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s10 = "rhbind.exe      : 1.6.25601.0 built by: PROJECTNGDR1" fullword ascii
    $s11 = "ilc.exe         : 1.6.25601.00 built by: PROJECTNGDR1" fullword ascii
    $s12 = "sg.exe          : 1.6.25601.00 built by: PROJECTNGDR1" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "62ec3dce1eba1b68f6a4511bb09f8c2c" and (8 of them)
    ) or (all of them)
}