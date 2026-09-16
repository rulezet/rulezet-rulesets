rule PEiD_01483_PCShrink_0_71_beta_ {
  meta:
    description = "[PCShrink 0.71 beta]"
    ep_only     = "true"

  strings:
    $a = { 01 AD 54 3A 40 00 FF B5 50 3A 40 00 6A 40 FF 95 88 3A 40 00 }

  condition:
    $a
}