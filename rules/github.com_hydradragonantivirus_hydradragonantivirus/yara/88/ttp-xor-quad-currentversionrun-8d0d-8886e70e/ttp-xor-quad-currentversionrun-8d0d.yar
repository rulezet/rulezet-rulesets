rule TTP_XOR_QUAD_CurrentVersionRun_8d0d {
  strings:
    $key_8d0d = { de 62 [2] fa 6c [2] d1 40 [2] ff 62 [2] eb 79 [2] e4 63 [2] fa 7e [2] f8 7f [2] e3 79 [2] ff 7e [2] e3 51 }

  condition:
    any of them
}