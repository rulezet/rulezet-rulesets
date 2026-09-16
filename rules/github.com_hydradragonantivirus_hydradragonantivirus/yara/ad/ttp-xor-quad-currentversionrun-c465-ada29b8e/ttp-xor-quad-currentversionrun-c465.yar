rule TTP_XOR_QUAD_CurrentVersionRun_c465 {
  strings:
    $key_c465 = { 97 0a [2] b3 04 [2] 98 28 [2] b6 0a [2] a2 11 [2] ad 0b [2] b3 16 [2] b1 17 [2] aa 11 [2] b6 16 [2] aa 39 }

  condition:
    any of them
}