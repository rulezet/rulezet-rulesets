rule TTP_XOR_QUAD_CurrentVersionRun_c445 {
  strings:
    $key_c445 = { 97 2a [2] b3 24 [2] 98 08 [2] b6 2a [2] a2 31 [2] ad 2b [2] b3 36 [2] b1 37 [2] aa 31 [2] b6 36 [2] aa 19 }

  condition:
    any of them
}