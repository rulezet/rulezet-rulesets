rule TTP_XOR_QUAD_CurrentVersionRun_c307 {
  strings:
    $key_c307 = { 90 68 [2] b4 66 [2] 9f 4a [2] b1 68 [2] a5 73 [2] aa 69 [2] b4 74 [2] b6 75 [2] ad 73 [2] b1 74 [2] ad 5b }

  condition:
    any of them
}