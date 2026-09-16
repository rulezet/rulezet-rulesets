rule TTP_XOR_QUAD_CurrentVersionRun_c365 {
  strings:
    $key_c365 = { 90 0a [2] b4 04 [2] 9f 28 [2] b1 0a [2] a5 11 [2] aa 0b [2] b4 16 [2] b6 17 [2] ad 11 [2] b1 16 [2] ad 39 }

  condition:
    any of them
}