rule PEiD_01511_PE_Spin_v0_4x_ {
  meta:
    description = "[PE Spin v0.4x]"
    ep_only     = "false"

  strings:
    $a = { EB 01 68 60 E8 00 00 00 00 8B }

  condition:
    $a
}