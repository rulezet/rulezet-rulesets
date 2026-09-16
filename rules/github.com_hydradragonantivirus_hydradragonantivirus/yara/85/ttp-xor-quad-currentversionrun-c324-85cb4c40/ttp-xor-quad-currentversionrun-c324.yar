rule TTP_XOR_QUAD_CurrentVersionRun_c324 {
  strings:
    $key_c324 = { 90 4b [2] b4 45 [2] 9f 69 [2] b1 4b [2] a5 50 [2] aa 4a [2] b4 57 [2] b6 56 [2] ad 50 [2] b1 57 [2] ad 78 }

  condition:
    any of them
}