rule TTP_XOR_QUAD_CurrentVersionRun_8d7b {
  strings:
    $key_8d7b = { de 14 [2] fa 1a [2] d1 36 [2] ff 14 [2] eb 0f [2] e4 15 [2] fa 08 [2] f8 09 [2] e3 0f [2] ff 08 [2] e3 27 }

  condition:
    any of them
}