rule TTP_XOR_QUAD_CurrentVersionRun_8d21 {
  strings:
    $key_8d21 = { de 4e [2] fa 40 [2] d1 6c [2] ff 4e [2] eb 55 [2] e4 4f [2] fa 52 [2] f8 53 [2] e3 55 [2] ff 52 [2] e3 7d }

  condition:
    any of them
}