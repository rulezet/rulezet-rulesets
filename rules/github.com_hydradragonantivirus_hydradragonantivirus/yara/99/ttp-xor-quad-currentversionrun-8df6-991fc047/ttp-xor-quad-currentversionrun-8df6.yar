rule TTP_XOR_QUAD_CurrentVersionRun_8df6 {
  strings:
    $key_8df6 = { de 99 [2] fa 97 [2] d1 bb [2] ff 99 [2] eb 82 [2] e4 98 [2] fa 85 [2] f8 84 [2] e3 82 [2] ff 85 [2] e3 aa }

  condition:
    any of them
}