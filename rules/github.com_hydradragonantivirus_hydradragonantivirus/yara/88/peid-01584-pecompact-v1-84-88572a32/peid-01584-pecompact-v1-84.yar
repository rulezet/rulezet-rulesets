rule PEiD_01584_PECompact_v1_84_ {
  meta:
    description = "[PECompact v1.84]"
    ep_only     = "true"

  strings:
    $a = { 33 C0 8B C4 83 C0 04 93 8B E3 8B 5B FC 81 }

  condition:
    $a
}