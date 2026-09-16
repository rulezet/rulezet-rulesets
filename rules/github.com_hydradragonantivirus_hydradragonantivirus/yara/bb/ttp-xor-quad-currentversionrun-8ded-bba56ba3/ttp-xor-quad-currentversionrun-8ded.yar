rule TTP_XOR_QUAD_CurrentVersionRun_8ded {
  strings:
    $key_8ded = { de 82 [2] fa 8c [2] d1 a0 [2] ff 82 [2] eb 99 [2] e4 83 [2] fa 9e [2] f8 9f [2] e3 99 [2] ff 9e [2] e3 b1 }

  condition:
    any of them
}