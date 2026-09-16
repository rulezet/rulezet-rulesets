rule PEiD_03507_XPack_1_52___1_64_ {
  meta:
    description = "[XPack 1.52 - 1.64]"
    ep_only     = "true"

  strings:
    $a = { 8B EC FA 33 C0 8E D0 BC ?? ?? 2E ?? ?? ?? ?? 2E ?? ?? ?? ?? EB }

  condition:
    $a
}