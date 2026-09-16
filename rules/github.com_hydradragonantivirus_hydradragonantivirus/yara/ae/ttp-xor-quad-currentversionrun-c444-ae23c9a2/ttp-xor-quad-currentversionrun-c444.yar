rule TTP_XOR_QUAD_CurrentVersionRun_c444 {
  strings:
    $key_c444 = { 97 2b [2] b3 25 [2] 98 09 [2] b6 2b [2] a2 30 [2] ad 2a [2] b3 37 [2] b1 36 [2] aa 30 [2] b6 37 [2] aa 18 }

  condition:
    any of them
}