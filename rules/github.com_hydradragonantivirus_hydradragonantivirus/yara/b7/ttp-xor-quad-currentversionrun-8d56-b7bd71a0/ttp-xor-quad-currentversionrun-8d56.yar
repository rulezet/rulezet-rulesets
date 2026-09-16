rule TTP_XOR_QUAD_CurrentVersionRun_8d56 {
  strings:
    $key_8d56 = { de 39 [2] fa 37 [2] d1 1b [2] ff 39 [2] eb 22 [2] e4 38 [2] fa 25 [2] f8 24 [2] e3 22 [2] ff 25 [2] e3 0a }

  condition:
    any of them
}