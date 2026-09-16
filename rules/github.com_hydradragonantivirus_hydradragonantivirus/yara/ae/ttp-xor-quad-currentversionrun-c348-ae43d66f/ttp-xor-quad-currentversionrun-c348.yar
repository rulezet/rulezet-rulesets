rule TTP_XOR_QUAD_CurrentVersionRun_c348 {
  strings:
    $key_c348 = { 90 27 [2] b4 29 [2] 9f 05 [2] b1 27 [2] a5 3c [2] aa 26 [2] b4 3b [2] b6 3a [2] ad 3c [2] b1 3b [2] ad 14 }

  condition:
    any of them
}