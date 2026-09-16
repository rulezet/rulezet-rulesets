rule TTP_XOR_QUAD_CurrentVersionRun_c436 {
  strings:
    $key_c436 = { 97 59 [2] b3 57 [2] 98 7b [2] b6 59 [2] a2 42 [2] ad 58 [2] b3 45 [2] b1 44 [2] aa 42 [2] b6 45 [2] aa 6a }

  condition:
    any of them
}