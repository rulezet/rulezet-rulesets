rule TTP_XOR_QUAD_CurrentVersionRun_ddc3 {
  strings:
    $key_ddc3 = { 8e ac [2] aa a2 [2] 81 8e [2] af ac [2] bb b7 [2] b4 ad [2] aa b0 [2] a8 b1 [2] b3 b7 [2] af b0 [2] b3 9f }

  condition:
    any of them
}