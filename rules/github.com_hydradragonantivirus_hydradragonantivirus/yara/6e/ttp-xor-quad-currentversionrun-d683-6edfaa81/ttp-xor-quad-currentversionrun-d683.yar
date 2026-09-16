rule TTP_XOR_QUAD_CurrentVersionRun_d683 {
  strings:
    $key_d683 = { 85 ec [2] a1 e2 [2] 8a ce [2] a4 ec [2] b0 f7 [2] bf ed [2] a1 f0 [2] a3 f1 [2] b8 f7 [2] a4 f0 [2] b8 df }

  condition:
    any of them
}