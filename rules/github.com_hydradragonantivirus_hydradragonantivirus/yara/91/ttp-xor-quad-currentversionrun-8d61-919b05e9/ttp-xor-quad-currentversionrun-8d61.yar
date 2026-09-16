rule TTP_XOR_QUAD_CurrentVersionRun_8d61 {
  strings:
    $key_8d61 = { de 0e [2] fa 00 [2] d1 2c [2] ff 0e [2] eb 15 [2] e4 0f [2] fa 12 [2] f8 13 [2] e3 15 [2] ff 12 [2] e3 3d }

  condition:
    any of them
}