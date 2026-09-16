rule _Virus_Hijack_Trojan_GenericKDZ_105924_185_1_Virus_Hijack_Trojan_387 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_185_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_231_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_237_1.vir, Virus.Infector_Gen.Heur.Mint.Hiamoe.20_1_1.vir, VirusShareTrojanClick331128_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2bb2947050574e099e0fe552980231d1d5fa55b069298b0c9f29431457554ca"
    hash2       = "a40b8fa734df8ea04b3e1d1c51a3945f9d70c4e86f8bda580f9b31c0d6dd4443"
    hash3       = "0e38d09d7f07504b85d3e0fde96b0813f2d0eb883ef14a926dcaa52902aa0b64"
    hash4       = "0ec2b92a7838dd7325db08b7a93f3deef19a5e11972ed64e753793f5f7ca6561"
    hash5       = "5865d276edcd50fd6f4b8e6b1734a9978b49ad4ebbd3c1b73f9723c140e80cf4"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArch" ascii
    $x2  = "'%s' appears to be a version 6.0 PDB; attempting to re-open with mspdb60.dll" fullword wide
    $s3  = "Annotations won't be removed w/o removing private information; -a ignored" fullword wide
    $s4  = "Error: %s, '%s' " fullword wide
    $s5  = "Error: %s, '%S' " fullword wide
    $s6  = "Error = %d, '%s', '%s'" fullword wide
    $s7  = "Old version of %s loaded, %d.%02d.%04d.%d" fullword wide
    $s8  = "Failed to convert '%s' to Ansi/MBCS" fullword wide
    $s9  = "usage: PDBCopy <source_pdb> <destination_pdb> [-p] [-s] [-vc6] [-?]" fullword wide
    $s10 = "Can't get address of procedure %s" fullword wide
    $s11 = "PDBCopy requires at least version %s" fullword wide
    $s12 = "Conversion of error text failed. Emitting ANSI:" fullword wide
    $s13 = "Can't load dll %s" fullword wide
    $s14 = "or one that implements PDB::CopyToW2" fullword wide
    $s15 = "9.00.30729.207 built by: QFE" fullword wide
    $s16 = "Cannot query version info for %s" fullword wide
    $s17 = "Unable to allocate %u bytes for version info." fullword wide
    $s18 = "re=\"X86\" name=\"pdbcopy\" type=\"win32\"></assemblyIdentity><dependency><dependentAssembly><assemblyIdentity type=\"win32\" na" ascii
    $s19 = "Can't open pdb file %S" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}