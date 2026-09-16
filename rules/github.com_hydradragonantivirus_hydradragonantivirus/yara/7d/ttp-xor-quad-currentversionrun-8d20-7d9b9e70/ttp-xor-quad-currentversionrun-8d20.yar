rule TTP_XOR_QUAD_CurrentVersionRun_8d20 {
  strings:
    $key_8d20 = { de 4f [2] fa 41 [2] d1 6d [2] ff 4f [2] eb 54 [2] e4 4e [2] fa 53 [2] f8 52 [2] e3 54 [2] ff 53 [2] e3 7c }

  condition:
    any of them
}