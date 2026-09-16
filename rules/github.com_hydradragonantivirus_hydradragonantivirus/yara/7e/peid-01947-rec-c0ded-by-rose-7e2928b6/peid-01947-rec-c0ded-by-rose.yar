rule PEiD_01947_REC__C0ded_by_ROSE_ {
  meta:
    description = "[REC, C0ded by ROSE]"
    ep_only     = "true"

  strings:
    $a = { 06 1E 0E 0E 07 1F B4 30 CD 21 86 E0 3D 00 03 73 ?? CD 20 EB }

  condition:
    $a
}