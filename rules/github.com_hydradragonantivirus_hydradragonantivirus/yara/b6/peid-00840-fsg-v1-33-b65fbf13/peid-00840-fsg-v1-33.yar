rule PEiD_00840_FSG_v1_33_ {
  meta:
    description = "[FSG v1.33]"
    ep_only     = "true"

  strings:
    $a = { BE A4 01 40 00 AD 93 AD 97 AD 56 96 B2 80 A4 B6 80 FF 13 73 }

  condition:
    $a
}