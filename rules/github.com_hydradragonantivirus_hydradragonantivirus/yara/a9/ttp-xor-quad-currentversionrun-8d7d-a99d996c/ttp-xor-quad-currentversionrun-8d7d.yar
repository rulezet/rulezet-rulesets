rule TTP_XOR_QUAD_CurrentVersionRun_8d7d {
  strings:
    $key_8d7d = { de 12 [2] fa 1c [2] d1 30 [2] ff 12 [2] eb 09 [2] e4 13 [2] fa 0e [2] f8 0f [2] e3 09 [2] ff 0e [2] e3 21 }

  condition:
    any of them
}