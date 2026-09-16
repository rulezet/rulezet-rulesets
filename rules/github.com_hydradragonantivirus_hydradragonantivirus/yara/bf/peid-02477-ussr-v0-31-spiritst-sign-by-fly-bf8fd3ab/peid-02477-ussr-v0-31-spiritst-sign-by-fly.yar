rule PEiD_02477_USSR_V0_31____SpiritST___Sign_by_fly_ {
  meta:
    description = "[USSR V0.31 -> SpiritST ! Sign by fly]"
    ep_only     = "false"

  strings:
    $a = { 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 2E 55 53 53 52 00 00 00 00 10 00 00 ?? ?? ?? ?? 00 10 00 00 ?? ?? ?? ?? 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 C0 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}