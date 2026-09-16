rule TTP_XOR_QUAD_CurrentVersionRun_c183 {
  strings:
    $key_c183 = { 92 ec [2] b6 e2 [2] 9d ce [2] b3 ec [2] a7 f7 [2] a8 ed [2] b6 f0 [2] b4 f1 [2] af f7 [2] b3 f0 [2] af df }

  condition:
    any of them
}