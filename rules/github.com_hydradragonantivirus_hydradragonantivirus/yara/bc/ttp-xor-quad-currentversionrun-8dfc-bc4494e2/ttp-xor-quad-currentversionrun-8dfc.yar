rule TTP_XOR_QUAD_CurrentVersionRun_8dfc {
  strings:
    $key_8dfc = { de 93 [2] fa 9d [2] d1 b1 [2] ff 93 [2] eb 88 [2] e4 92 [2] fa 8f [2] f8 8e [2] e3 88 [2] ff 8f [2] e3 a0 }

  condition:
    any of them
}