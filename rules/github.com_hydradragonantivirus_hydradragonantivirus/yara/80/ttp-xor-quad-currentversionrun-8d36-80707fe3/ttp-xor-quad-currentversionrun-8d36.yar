rule TTP_XOR_QUAD_CurrentVersionRun_8d36 {
  strings:
    $key_8d36 = { de 59 [2] fa 57 [2] d1 7b [2] ff 59 [2] eb 42 [2] e4 58 [2] fa 45 [2] f8 44 [2] e3 42 [2] ff 45 [2] e3 6a }

  condition:
    any of them
}