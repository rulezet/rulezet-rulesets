rule TTP_XOR_QUAD_CurrentVersionRun_c455 {
  strings:
    $key_c455 = { 97 3a [2] b3 34 [2] 98 18 [2] b6 3a [2] a2 21 [2] ad 3b [2] b3 26 [2] b1 27 [2] aa 21 [2] b6 26 [2] aa 09 }

  condition:
    any of them
}