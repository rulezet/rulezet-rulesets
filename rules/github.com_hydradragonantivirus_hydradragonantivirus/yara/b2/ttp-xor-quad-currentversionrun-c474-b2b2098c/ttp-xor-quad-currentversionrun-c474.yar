rule TTP_XOR_QUAD_CurrentVersionRun_c474 {
  strings:
    $key_c474 = { 97 1b [2] b3 15 [2] 98 39 [2] b6 1b [2] a2 00 [2] ad 1a [2] b3 07 [2] b1 06 [2] aa 00 [2] b6 07 [2] aa 28 }

  condition:
    any of them
}