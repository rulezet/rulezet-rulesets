rule PEiD_01669_Petite_1_3_ {
  meta:
    description = "[Petite 1.3]"
    ep_only     = "false"

  strings:
    $a = { 66 9C 60 50 8D 88 00 F0 00 00 8D 90 04 16 00 00 8B DC 8B E1 }

  condition:
    $a
}