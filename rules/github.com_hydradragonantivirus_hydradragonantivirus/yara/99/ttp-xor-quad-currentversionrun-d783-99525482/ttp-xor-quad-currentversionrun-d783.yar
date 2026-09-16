rule TTP_XOR_QUAD_CurrentVersionRun_d783 {
  strings:
    $key_d783 = { 84 ec [2] a0 e2 [2] 8b ce [2] a5 ec [2] b1 f7 [2] be ed [2] a0 f0 [2] a2 f1 [2] b9 f7 [2] a5 f0 [2] b9 df }

  condition:
    any of them
}