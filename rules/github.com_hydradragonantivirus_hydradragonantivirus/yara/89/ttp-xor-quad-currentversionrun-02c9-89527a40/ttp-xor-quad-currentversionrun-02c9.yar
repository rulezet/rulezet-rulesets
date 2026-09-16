rule TTP_XOR_QUAD_CurrentVersionRun_02c9 {
  strings:
    $key_02c9 = { 51 a6 [2] 75 a8 [2] 5e 84 [2] 70 a6 [2] 64 bd [2] 6b a7 [2] 75 ba [2] 77 bb [2] 6c bd [2] 70 ba [2] 6c 95 }

  condition:
    any of them
}