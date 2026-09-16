rule TTP_XOR_QUAD_CurrentVersionRun_c408 {
  strings:
    $key_c408 = { 97 67 [2] b3 69 [2] 98 45 [2] b6 67 [2] a2 7c [2] ad 66 [2] b3 7b [2] b1 7a [2] aa 7c [2] b6 7b [2] aa 54 }

  condition:
    any of them
}