rule TTP_XOR_QUAD_CurrentVersionRun_afdf {
  strings:
    $key_afdf = { fc b0 [2] d8 be [2] f3 92 [2] dd b0 [2] c9 ab [2] c6 b1 [2] d8 ac [2] da ad [2] c1 ab [2] dd ac [2] c1 83 }

  condition:
    any of them
}