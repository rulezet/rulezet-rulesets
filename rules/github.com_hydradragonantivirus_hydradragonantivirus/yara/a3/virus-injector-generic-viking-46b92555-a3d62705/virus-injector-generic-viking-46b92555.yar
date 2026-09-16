rule Virus_Injector_Generic_Viking_46B92555 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.46B92555.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adf0b910f6946d2182005b7acd35567cb63b4dd27bcc7554e3fe5238b2b2c79a"

  strings:
    $s1 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
    $s2 = "@Adobe End User License Agreemen" fullword wide
    $s3 = "(c) Adobe Systems Incorporated.  All rights reserved." fullword wide
    $s4 = "aLky;," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}