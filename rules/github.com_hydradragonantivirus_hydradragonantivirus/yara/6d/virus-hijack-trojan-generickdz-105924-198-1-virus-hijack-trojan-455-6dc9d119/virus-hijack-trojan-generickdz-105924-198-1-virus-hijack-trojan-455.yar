import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_198_1_Virus_Hijack_Trojan_455 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_198_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_19_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72cb568852aefb8035aad20d72a8083225ebc43807367926e971434cb2daf99e"
    hash2       = "8047b98874aa31f346742a949d0a47ce3b4ba175dbfec9fefd06019aad0d4af8"

  strings:
    $s1  = "  -o - output file template" fullword ascii
    $s2  = "ccomps: component %d not found in graph %s - ignored" fullword ascii
    $s3  = "ccomps: node %s not found in graph %s - ignored" fullword ascii
    $s4  = "ccomps: final index %d < start index %d in -X%s flag - ignored" fullword ascii
    $s5  = "  -n - do not induce subgraphs" fullword ascii
    $s6  = "Usage: ccomps [-svenCx?] [-X[#%]s[-f]] [-o<out template>] <files>" fullword ascii
    $s7  = "  -e - do not induce edges" fullword ascii
    $s8  = "  -z - sort by size, largest first" fullword ascii
    $s9  = "  -x - external" fullword ascii
    $s10 = "ccomps: option -%c unrecognized - ignored" fullword ascii
    $s11 = "ccomps: number expected in -X%s flag - ignored" fullword ascii
    $s12 = "  -X - extract component" fullword ascii
    $s13 = "ccomps: option -%c missing argument - ignored" fullword ascii
    $s14 = "ccomps: node %s not found in graph %s" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (8 of them)
    ) or (all of them)
}