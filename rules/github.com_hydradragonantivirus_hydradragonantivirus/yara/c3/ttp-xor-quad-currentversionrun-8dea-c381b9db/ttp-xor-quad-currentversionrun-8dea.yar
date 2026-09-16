rule TTP_XOR_QUAD_CurrentVersionRun_8dea {
  strings:
    $key_8dea = { de 85 [2] fa 8b [2] d1 a7 [2] ff 85 [2] eb 9e [2] e4 84 [2] fa 99 [2] f8 98 [2] e3 9e [2] ff 99 [2] e3 b6 }

  condition:
    any of them
}