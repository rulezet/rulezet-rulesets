rule PEiD_02095_SimplePack_V1_1X__Method1_____bagie___Sign_by_fly_ {
  meta:
    description = "[SimplePack V1.1X (Method1) -> bagie ! Sign by fly]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 5B 8D 5B FA BD ?? ?? ?? ?? 8B 7D 3C 8D 74 3D 00 8D BE F8 00 00 00 0F B7 76 06 4E 8B 47 10 09 C0 }

  condition:
    $a
}