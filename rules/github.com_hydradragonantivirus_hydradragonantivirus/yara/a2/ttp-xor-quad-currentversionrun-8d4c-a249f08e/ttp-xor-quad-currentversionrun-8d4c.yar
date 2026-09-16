rule TTP_XOR_QUAD_CurrentVersionRun_8d4c {
  strings:
    $key_8d4c = { de 23 [2] fa 2d [2] d1 01 [2] ff 23 [2] eb 38 [2] e4 22 [2] fa 3f [2] f8 3e [2] e3 38 [2] ff 3f [2] e3 10 }

  condition:
    any of them
}