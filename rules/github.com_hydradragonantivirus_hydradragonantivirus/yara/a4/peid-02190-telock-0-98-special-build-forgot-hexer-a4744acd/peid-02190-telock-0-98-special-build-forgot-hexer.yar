rule PEiD_02190_tElock_0_98_Special_Build____forgot___heXer_ {
  meta:
    description = "[tElock 0.98 Special Build -> forgot & heXer]"
    ep_only     = "true"

  strings:
    $a = { E9 99 D7 FF FF 00 00 00 ?? ?? ?? ?? AA ?? ?? 00 00 00 00 00 00 00 00 00 CA }

  condition:
    $a
}