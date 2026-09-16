rule TTP_XOR_QUAD_CurrentVersionRun_c415 {
  strings:
    $key_c415 = { 97 7a [2] b3 74 [2] 98 58 [2] b6 7a [2] a2 61 [2] ad 7b [2] b3 66 [2] b1 67 [2] aa 61 [2] b6 66 [2] aa 49 }

  condition:
    any of them
}