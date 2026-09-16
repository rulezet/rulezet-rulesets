rule TTP_XOR_QUAD_CurrentVersionRun_8dfd {
  strings:
    $key_8dfd = { de 92 [2] fa 9c [2] d1 b0 [2] ff 92 [2] eb 89 [2] e4 93 [2] fa 8e [2] f8 8f [2] e3 89 [2] ff 8e [2] e3 a1 }

  condition:
    any of them
}