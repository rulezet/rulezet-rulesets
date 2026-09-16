rule TTP_XOR_QUAD_CurrentVersionRun_dec2 {
  strings:
    $key_dec2 = { 8d ad [2] a9 a3 [2] 82 8f [2] ac ad [2] b8 b6 [2] b7 ac [2] a9 b1 [2] ab b0 [2] b0 b6 [2] ac b1 [2] b0 9e }

  condition:
    any of them
}