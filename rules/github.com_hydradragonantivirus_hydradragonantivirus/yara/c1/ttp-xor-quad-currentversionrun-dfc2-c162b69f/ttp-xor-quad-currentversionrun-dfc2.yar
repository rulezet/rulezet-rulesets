rule TTP_XOR_QUAD_CurrentVersionRun_dfc2 {
  strings:
    $key_dfc2 = { 8c ad [2] a8 a3 [2] 83 8f [2] ad ad [2] b9 b6 [2] b6 ac [2] a8 b1 [2] aa b0 [2] b1 b6 [2] ad b1 [2] b1 9e }

  condition:
    any of them
}