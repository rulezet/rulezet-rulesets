rule TTP_XOR_QUAD_CurrentVersionRun_8d22 {
  strings:
    $key_8d22 = { de 4d [2] fa 43 [2] d1 6f [2] ff 4d [2] eb 56 [2] e4 4c [2] fa 51 [2] f8 50 [2] e3 56 [2] ff 51 [2] e3 7e }

  condition:
    any of them
}