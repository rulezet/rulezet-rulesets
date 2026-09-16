import "pe"
rule _Trojan_Autorun_Gen_Heur_Mint_Murphy_3_329_1_Trojan_Autorun_Gen__462 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Heur.Mint.Murphy.3_329_1.vir, Trojan.Autorun_Gen.Heur.Mint.Murphy.3_88_1.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.gmZbaKq9kbjb_1_1.vir, Trojan.Autorun_Gen.Trojan.Backdoor2.hmZbaKq9kbjb_3_1.vir, Trojan.Autorun_Gen.Variant.Barys.121928_15_1.vir, Trojan.Autorun_Gen.Variant.Ransom.Phobos.169_15_1.vir, Trojan.Autorun_Generic.Dacic.AAD0835C.A.6E3514F8_6.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_103_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_134_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_161_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_183_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_199_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_35_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_75_1.vir, Trojan.Autorun_Generic.Malware.SF!dld!.D800E25F_93_1.vir, Trojan.Autorun_Trojan.GenericKD.72446609_1_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGFgBch.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGFgBch_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGFgBch_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aGFgBch_3.vir, Virus.Hijack_Trojan.GenericKDZ.98113_86.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98e89108bfef41773d2a32b496f9dccd1f08337c98c08631131adc83a01bc828"
    hash2       = "7def91a70727c0cfc75b000ebe342280c8b8d0bd24ff258f8b7ebdd2e49fcfe0"
    hash3       = "621f8f53df1f570fb50913f12b7f9a99fb315a28c75180cf17bd895b9d1b2d18"
    hash4       = "62b4a94fc197ad5bdda9697800fd29767866a44067ae934dfaa1794ac2804b77"
    hash5       = "b19916810b3486343877ba5435edad26999ff5ad2014415845a4bec9ac16a724"
    hash6       = "42452c7bb9278df1ada42917fc7e7a34c6df3708f74a2999d62795729f01a014"
    hash7       = "9adb34836ddb2979bbc7f3593c2da69951f25a8013fc9db2b4fd3a5d589285b1"
    hash8       = "033ff39b43b3550816354021995181dc69ab4f33a2b66f2c4673d37dc800a790"
    hash9       = "633778a2c6fe64295dd2b8948c5e88b8e77cbb5c5541108f2f8e04c109c1c672"
    hash10      = "5b0f6657fd44584b9d5395bb8fd90604ece5edd1324f26abcd668f73ca0ac874"
    hash11      = "66b86e41499ed32c009283d37bfb92f54a194a86495a2e0283127fc3c68dc3d1"
    hash12      = "6260f0a85d303ae58acdc2edb68a6dad0bf827407f2ad9d3c04e7222d04ec2f1"
    hash13      = "36f29b88ca450e19938dd7f7a1dd62348333d5861822e3b77769c0f9357fa635"
    hash14      = "c14405078320269fe2bd86e487894e1cfde7f951dc2d58c30121fe373b2c95b1"
    hash15      = "367b373d4b218e80df0b08eca7ccd04e9d3dfa1023c153408da1748e5ea0db53"
    hash16      = "d617e8a98d1958d51d7570cb0fe601e392ab8722408bacc66c0b7a6ed5733658"
    hash17      = "a8466612c0a3724615a129c9e49c806766b47d94f18ea08f84a61e5514d4f938"
    hash18      = "3db9c189d9a18fdb8ebe283a98628def3091d1c1ee890dc13dd5b93cf71affa7"
    hash19      = "9f13e2d44c6919332dc61e5381b39bac4afa2215076f96b300e060e51e2abffb"
    hash20      = "952265d3a22e13bd5c6d91a3622d15010f5d32a883b4b655077e1de9a8c53241"
    hash21      = "aaabbba7909064d62c2331c84a67a7de3476c42da88492ff17d3eb09abdab730"

  strings:
    $s1  = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as Professional Users.iod. See" ascii
    $s2  = "access to the Oracle iSupport program may not be licensed as Employee Users, but must be licensed as Professional Users.iod. See" ascii
    $s3  = "Named User Plus: is defined as an individual authorized by you to use the programs which are installed on a single server ory or" ascii
    $s4  = "option in conjunction with EAM, you are required to maintain licenses for the equivalent number of EAM Users licensed andm licen" ascii
    $s5  = "der or download a backup copy of the software from" fullword ascii
    $s6  = "Employee User: is defined as an individual authorized bymessage dialog." fullword ascii
    $s7  = "option in conjunction with EAM, you are required to maintain licenses for the equivalent number of EAM Users licensed andm licen" ascii
    $s8  = "GIVES NO EXPRESS WARRANOracle University Online Service: the Oracle University Online Service is a web based learning environmen" ascii
    $s9  = "and services at the list price in effect at tthose features in any way that could interfere with anyone else" fullword ascii
    $s10 = " the software activation screens or other accompanying" fullword ascii
    $s11 = "t comprised of" fullword ascii
    $s12 = "Management application from any source (not manually entered by licensed Order Management Users, Professional UsersA TION. YOU A" ascii
    $s13 = "Management application from any source (not manually entered by licensed Order Management Users, Professional UsersA TION. YOU A" ascii
    $s14 = "GIVES NO EXPRESS WARRANOracle University Online Service: the Oracle University Online Service is a web based learning environmen" ascii
    $s15 = "Named User Plus: is defined as an individual authorized by you to use the programs which are installed on a single server ory or" ascii
    $s16 = "agreemenThank you for choosing a computer preinstalled with Microsoft Office 2013. This is a license agreement" fullword ascii
    $s17 = "ity) or software will stop running." fullword ascii
    $s18 = "Provider may choose to either modify the Material to be non-infringing (while substantially preserving its utility or functional" ascii
    $s19 = "use either party" fullword ascii
    $s20 = "se is perpetual and shall continue unless terminated as" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a317f33d638ad921f1adf2f375a4b640" and (8 of them)
    ) or (all of them)
}