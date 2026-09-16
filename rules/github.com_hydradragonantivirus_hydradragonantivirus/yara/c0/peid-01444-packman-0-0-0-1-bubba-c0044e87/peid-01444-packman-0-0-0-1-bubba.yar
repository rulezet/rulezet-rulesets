rule PEiD_01444_Packman_0_0_0_1____bubba_ {
  meta:
    description = "[Packman 0.0.0.1 -> bubba]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 00 00 00 00 58 8D A8 ?? FE FF FF 8D 98 ?? ?? ?? FF 8D ?? ?? 01 00 00 }

  condition:
    $a
}