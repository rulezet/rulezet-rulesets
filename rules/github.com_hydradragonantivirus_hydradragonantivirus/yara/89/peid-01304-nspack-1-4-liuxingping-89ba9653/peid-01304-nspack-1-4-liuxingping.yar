rule PEiD_01304_NsPack_1_4____Liuxingping_ {
  meta:
    description = "[NsPack 1.4 -> Liuxingping]"
    ep_only     = "true"

  strings:
    $a = { 9C 60 E8 00 00 00 00 5D B8 ?? ?? 40 00 2D ?? ?? 40 00 }

  condition:
    $a
}