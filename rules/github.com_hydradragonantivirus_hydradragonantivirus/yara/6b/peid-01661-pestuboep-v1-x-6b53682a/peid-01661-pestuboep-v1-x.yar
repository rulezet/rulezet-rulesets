rule PEiD_01661_PEStubOEP_v1_x_ {
  meta:
    description = "[PEStubOEP v1.x]"
    ep_only     = "false"

  strings:
    $a = { 40 48 BE 00 ?? ?? 00 40 48 60 33 C0 B8 ?? ?? ?? 00 FF E0 C3 C3 }

  condition:
    $a
}