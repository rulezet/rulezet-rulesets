rule TTP_XOR_QUAD_CurrentVersionRun_8d4e {
  strings:
    $key_8d4e = { de 21 [2] fa 2f [2] d1 03 [2] ff 21 [2] eb 3a [2] e4 20 [2] fa 3d [2] f8 3c [2] e3 3a [2] ff 3d [2] e3 12 }

  condition:
    any of them
}