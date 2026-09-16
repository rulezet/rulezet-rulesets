rule TTP_XOR_QUAD_CurrentVersionRun_ccc3 {
  strings:
    $key_ccc3 = { 9f ac [2] bb a2 [2] 90 8e [2] be ac [2] aa b7 [2] a5 ad [2] bb b0 [2] b9 b1 [2] a2 b7 [2] be b0 [2] a2 9f }

  condition:
    any of them
}