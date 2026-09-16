rule PEiD_02099_SimplePack_V1_1X_V1_2X__Method2_____bagie_ {
  meta:
    description = "[SimplePack V1.1X-V1.2X (Method2) -> bagie]"
    ep_only     = "true"

  strings:
    $a = { 4D 5A 90 EB 01 00 52 E9 ?? 01 00 00 50 45 00 00 4C 01 02 00 }

  condition:
    $a
}