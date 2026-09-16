rule TTP_XOR_QUAD_CurrentVersionRun_dec3 {
  strings:
    $key_dec3 = { 8d ac [2] a9 a2 [2] 82 8e [2] ac ac [2] b8 b7 [2] b7 ad [2] a9 b0 [2] ab b1 [2] b0 b7 [2] ac b0 [2] b0 9f }

  condition:
    any of them
}