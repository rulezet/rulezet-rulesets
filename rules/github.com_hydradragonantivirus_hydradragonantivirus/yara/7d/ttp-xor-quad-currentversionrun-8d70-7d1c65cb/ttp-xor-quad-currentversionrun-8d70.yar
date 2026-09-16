rule TTP_XOR_QUAD_CurrentVersionRun_8d70 {
  strings:
    $key_8d70 = { de 1f [2] fa 11 [2] d1 3d [2] ff 1f [2] eb 04 [2] e4 1e [2] fa 03 [2] f8 02 [2] e3 04 [2] ff 03 [2] e3 2c }

  condition:
    any of them
}