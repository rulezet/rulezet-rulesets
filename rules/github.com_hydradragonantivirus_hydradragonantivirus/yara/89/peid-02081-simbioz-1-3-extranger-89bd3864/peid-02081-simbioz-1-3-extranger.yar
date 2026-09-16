rule PEiD_02081_SimbiOZ_1_3____Extranger_ {
  meta:
    description = "[SimbiOZ 1.3 -> Extranger]"
    ep_only     = "true"

  strings:
    $a = { 57 57 8D 7C 24 04 50 B8 00 ?? ?? ?? AB 58 5F C3 }

  condition:
    $a
}