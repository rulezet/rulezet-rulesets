rule PEiD_00448_Cygwin32_ {
  meta:
    description = "[Cygwin32]"
    ep_only     = "true"

  strings:
    $a = { 55 89 E5 83 EC 04 83 3D }

  condition:
    $a
}