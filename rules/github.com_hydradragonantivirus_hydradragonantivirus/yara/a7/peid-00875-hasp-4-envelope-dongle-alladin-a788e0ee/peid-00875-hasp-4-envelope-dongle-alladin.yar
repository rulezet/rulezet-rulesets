rule PEiD_00875_Hasp_4_envelope_dongle__Alladin__ {
  meta:
    description = "[Hasp 4 envelope dongle (Alladin)]"
    ep_only     = "true"

  strings:
    $a = { 10 02 D0 51 0F 00 83 }

  condition:
    $a
}