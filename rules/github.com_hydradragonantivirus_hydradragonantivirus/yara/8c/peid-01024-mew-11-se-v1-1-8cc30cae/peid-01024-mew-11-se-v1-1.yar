rule PEiD_01024_MEW_11_SE_v1_1_ {
  meta:
    description = "[MEW 11 SE v1.1]"
    ep_only     = "false"

  strings:
    $a = { E9 ?? ?? ?? FF 0C ?? 00 00 00 00 00 00 00 00 00 00 }

  condition:
    $a
}