rule TTP_XOR_QUAD_CurrentVersionRun_acdf {
  strings:
    $key_acdf = { ff b0 [2] db be [2] f0 92 [2] de b0 [2] ca ab [2] c5 b1 [2] db ac [2] d9 ad [2] c2 ab [2] de ac [2] c2 83 }

  condition:
    any of them
}