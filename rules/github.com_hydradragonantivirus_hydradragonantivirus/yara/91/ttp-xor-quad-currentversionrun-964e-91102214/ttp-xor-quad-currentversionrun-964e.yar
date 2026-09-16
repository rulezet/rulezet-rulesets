rule TTP_XOR_QUAD_CurrentVersionRun_964e {
  strings:
    $key_964e = { c5 21 [2] e1 2f [2] ca 03 [2] e4 21 [2] f0 3a [2] ff 20 [2] e1 3d [2] e3 3c [2] f8 3a [2] e4 3d [2] f8 12 }

  condition:
    any of them
}