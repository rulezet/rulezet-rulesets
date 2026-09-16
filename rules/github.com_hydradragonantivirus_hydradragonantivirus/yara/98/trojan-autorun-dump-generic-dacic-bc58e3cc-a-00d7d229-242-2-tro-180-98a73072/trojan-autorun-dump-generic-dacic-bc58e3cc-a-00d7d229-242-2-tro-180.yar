import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_242_2_Tro_180 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_242_2.vir, Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_243_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.i8Y@aerna7n_6_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.k8Z@aSl2g6j_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ec02253eb05e5caaa66f3df8af7faf456e6a864c4168c3aee58a026d7909425"
    hash2       = "31709b0448beb93c6e69b24dbed5a185a0993dd96fa8d129191de625de88d755"
    hash3       = "56a4b09e578c3da8646b6ead5f7f8bab22dc056f2dee42f349613e6dfc00bdb6"
    hash4       = "af074b93a8ed36bfe898c4a842b6d083d33b3da95e3d5033f8699319c949f31a"

  strings:
    $s1  = "\" id=\"W5M0MpCehiHzreSzNTczkc9d\"?> <x:xmpmeta xmlns:x=\"adobe:ns:meta/\" x:xmptk=\"Adobe XMP Core 5.0-c061 64.140949, 2010/12/" ascii
    $s2  = "obe.com/xap/1.0/sType/ResourceRef#\" xmp:CreatorTool=\"Adobe Photoshop CS5.1 Windows\" xmp:CreateDate=\"2017-01-03T12:49:37+05:3" ascii
    $s3  = "Login Window" fullword ascii
    $s4  = "Login as:-" fullword ascii
    $s5  = "\"xmp.iid:FA6BD3AC2811E711AEF58B68CDBB6E6A\" stEvt:when=\"2017-03-25T12:31:07+05:30\" stEvt:softwareAgent=\"Adobe Photoshop CS5." ascii
    $s6  = "9:37+05:30\" stEvt:softwareAgent=\"Adobe Photoshop CS5.1 Windows\"/> <rdf:li stEvt:action=\"saved\" stEvt:instanceID=\"xmp.iid:F" ascii
    $s7  = "* Student ID Field is Required" fullword wide
    $s8  = "* Student Name Field is Required" fullword wide
    $s9  = "* Student CNIC Field is Required" fullword wide
    $s10 = "* Student program Field is Required" fullword wide
    $s11 = ".did:AEA56C3273D1E61192BEEE36942D1B1C\"/> </rdf:Description> </rdf:RDF> </x:xmpmeta>                                            " ascii
    $s12 = "05+05:30\" stEvt:softwareAgent=\"Adobe Photoshop CS5.1 Windows\" stEvt:changed=\"/\"/> <rdf:li stEvt:action=\"saved\" stEvt:inst" ascii
    $s13 = "reAgent=\"Adobe Photoshop CS5.1 Windows\" stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=" ascii
    $s14 = "C2811E711AEF58B68CDBB6E6A\" stEvt:when=\"2017-03-25T12:30:05+05:30\" stEvt:softwareAgent=\"Adobe Photoshop CS5.1 Windows\" stEvt" ascii
    $s15 = "Learning Management system" fullword ascii
    $s16 = "ncestors> <rdf:Bag> <rdf:li>DFE3D5E91A963CC080DD170463B25D19</rdf:li> </rdf:Bag> </photoshop:DocumentAncestors> <xmpMM:History> " ascii
    $s17 = "Student Name" fullword ascii
    $s18 = "Student ID" fullword ascii
    $s19 = "Student Registraion" fullword ascii
    $s20 = "Student Register successfully" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (8 of them)
    ) or (all of them)
}