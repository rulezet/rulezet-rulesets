rule PEiD_02101_SimplePack_V1_21_build_09_09__Method2_____bagie_ {
  meta:
    description = "[SimplePack V1.21.build.09.09 (Method2) -> bagie]"
    ep_only     = "true"

  strings:
    $a = { 4D 5A 90 EB 01 00 52 E9 8A 01 00 00 50 45 00 00 4C 01 02 00 00 00 00 00 00 00 00 00 00 00 00 00 E0 00 0F 03 0B 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0C 00 00 00 00 ?? ?? ?? 00 10 00 00 00 02 00 00 01 00 00 00 00 00 00 00 04 }

  condition:
    $a
}