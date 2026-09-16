rule PEiD_00859_Gleam_1_00_ {
  meta:
    description = "[Gleam 1.00]"
    ep_only     = "false"

  strings:
    $a = { 83 EC 0C 53 56 57 E8 24 02 00 }

  condition:
    $a
}