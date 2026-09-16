rule TTP_XOR_QUAD_CurrentVersionRun_8d41 {
  strings:
    $key_8d41 = { de 2e [2] fa 20 [2] d1 0c [2] ff 2e [2] eb 35 [2] e4 2f [2] fa 32 [2] f8 33 [2] e3 35 [2] ff 32 [2] e3 1d }

  condition:
    any of them
}