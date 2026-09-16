rule TTP_XOR_QUAD_CurrentVersionRun_e2c9 {
  strings:
    $key_e2c9 = { b1 a6 [2] 95 a8 [2] be 84 [2] 90 a6 [2] 84 bd [2] 8b a7 [2] 95 ba [2] 97 bb [2] 8c bd [2] 90 ba [2] 8c 95 }

  condition:
    any of them
}