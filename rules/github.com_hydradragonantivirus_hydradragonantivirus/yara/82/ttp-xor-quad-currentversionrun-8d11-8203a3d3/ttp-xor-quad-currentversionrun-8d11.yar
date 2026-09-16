rule TTP_XOR_QUAD_CurrentVersionRun_8d11 {
  strings:
    $key_8d11 = { de 7e [2] fa 70 [2] d1 5c [2] ff 7e [2] eb 65 [2] e4 7f [2] fa 62 [2] f8 63 [2] e3 65 [2] ff 62 [2] e3 4d }

  condition:
    any of them
}