rule TTP_XOR_QUAD_CurrentVersionRun_e5c9 {
  strings:
    $key_e5c9 = { b6 a6 [2] 92 a8 [2] b9 84 [2] 97 a6 [2] 83 bd [2] 8c a7 [2] 92 ba [2] 90 bb [2] 8b bd [2] 97 ba [2] 8b 95 }

  condition:
    any of them
}