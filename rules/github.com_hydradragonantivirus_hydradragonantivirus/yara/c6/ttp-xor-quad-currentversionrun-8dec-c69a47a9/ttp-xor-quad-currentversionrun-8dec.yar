rule TTP_XOR_QUAD_CurrentVersionRun_8dec {
  strings:
    $key_8dec = { de 83 [2] fa 8d [2] d1 a1 [2] ff 83 [2] eb 98 [2] e4 82 [2] fa 9f [2] f8 9e [2] e3 98 [2] ff 9f [2] e3 b0 }

  condition:
    any of them
}