rule TTP_XOR_QUAD_CurrentVersionRun_8d1c {
  strings:
    $key_8d1c = { de 73 [2] fa 7d [2] d1 51 [2] ff 73 [2] eb 68 [2] e4 72 [2] fa 6f [2] f8 6e [2] e3 68 [2] ff 6f [2] e3 40 }

  condition:
    any of them
}