rule Virus_Hijack_Gen_Trojan_ShellObject_t8Z_ae0D4Vj_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.t8Z@ae0D4Vj_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7ed5eeb1d9ff0a761ff64f939e5c833e58eb351221cbaa012ad1c83e9084734"

  strings:
    $s1 = " stEvt:changed=\"/\"/> </rdf:Seq> </xmpMM:History> <xmpMM:DerivedFrom stRef:instanceID=\"xmp.iid:d9d77401-7124-ed42-8b71-4014b65" ascii
    $s2 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii
    $s3 = "df:Description> </rdf:RDF> </x:xmpmeta>                                                                                         " ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}