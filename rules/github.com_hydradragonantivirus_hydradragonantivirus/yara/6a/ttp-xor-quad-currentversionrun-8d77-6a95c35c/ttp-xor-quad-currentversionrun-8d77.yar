rule TTP_XOR_QUAD_CurrentVersionRun_8d77 {
  strings:
    $key_8d77 = { de 18 [2] fa 16 [2] d1 3a [2] ff 18 [2] eb 03 [2] e4 19 [2] fa 04 [2] f8 05 [2] e3 03 [2] ff 04 [2] e3 2b }

  condition:
    any of them
}