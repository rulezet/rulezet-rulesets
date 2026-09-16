rule TTP_XOR_QUAD_CurrentVersionRun_c479 {
  strings:
    $key_c479 = { 97 16 [2] b3 18 [2] 98 34 [2] b6 16 [2] a2 0d [2] ad 17 [2] b3 0a [2] b1 0b [2] aa 0d [2] b6 0a [2] aa 25 }

  condition:
    any of them
}