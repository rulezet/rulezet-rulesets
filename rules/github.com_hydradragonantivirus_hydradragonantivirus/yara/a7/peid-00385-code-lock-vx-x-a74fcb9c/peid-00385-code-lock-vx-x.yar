rule PEiD_00385_Code_Lock_vx_x_ {
  meta:
    description = "[Code-Lock vx.x]"
    ep_only     = "true"

  strings:
    $a = { 43 4F 44 45 2D 4C 4F 43 4B 2E 4F 43 58 00 }

  condition:
    $a
}