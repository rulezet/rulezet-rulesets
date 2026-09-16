rule TTP_XOR_QUAD_CurrentVersionRun_dcc3 {
  strings:
    $key_dcc3 = { 8f ac [2] ab a2 [2] 80 8e [2] ae ac [2] ba b7 [2] b5 ad [2] ab b0 [2] a9 b1 [2] b2 b7 [2] ae b0 [2] b2 9f }

  condition:
    any of them
}