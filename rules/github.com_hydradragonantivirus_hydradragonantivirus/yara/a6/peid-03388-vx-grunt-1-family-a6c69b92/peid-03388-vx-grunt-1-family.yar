rule PEiD_03388_Vx__GRUNT_1_Family_ {
  meta:
    description = "[Vx: GRUNT.1.Family]"
    ep_only     = "true"

  strings:
    $a = { 01 B9 ?? 00 31 17 }

  condition:
    $a
}