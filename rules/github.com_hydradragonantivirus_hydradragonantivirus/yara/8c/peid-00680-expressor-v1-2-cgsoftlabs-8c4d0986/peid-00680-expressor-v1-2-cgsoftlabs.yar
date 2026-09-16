rule PEiD_00680_eXPressor_v1_2____CGSoftLabs_ {
  meta:
    description = "[eXPressor v1.2 -> CGSoftLabs]"
    ep_only     = "false"

  strings:
    $a = "ExPr-v.1.2."

  condition:
    $a
}