rule PEiD_00362_Can2Exe_v0_01_ {
  meta:
    description = "[Can2Exe v0.01]"
    ep_only     = "true"

  strings:
    $a = { 0E 1F 0E 07 E8 ?? ?? E8 ?? ?? 3A C6 73 }

  condition:
    $a
}