rule PEiD_02096_SimplePack_V1_1X__Method2_____bagie___Sign_by_fly_ {
  meta:
    description = "[SimplePack V1.1X (Method2) -> bagie ! Sign by fly]"
    ep_only     = "false"

  strings:
    $a = { 4D 5A 90 EB 01 00 52 E9 89 01 00 00 50 45 00 00 4C 01 02 00 }

  condition:
    $a
}