rule TTP_XOR_QUAD_CurrentVersionRun_e396 {
  strings:
    $key_e396 = { b0 f9 [2] 94 f7 [2] bf db [2] 91 f9 [2] 85 e2 [2] 8a f8 [2] 94 e5 [2] 96 e4 [2] 8d e2 [2] 91 e5 [2] 8d ca }

  condition:
    any of them
}