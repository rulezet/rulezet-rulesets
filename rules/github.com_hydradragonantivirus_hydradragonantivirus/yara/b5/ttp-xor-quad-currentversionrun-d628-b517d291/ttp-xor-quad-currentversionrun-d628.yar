rule TTP_XOR_QUAD_CurrentVersionRun_d628 {
  strings:
    $key_d628 = { 85 47 [2] a1 49 [2] 8a 65 [2] a4 47 [2] b0 5c [2] bf 46 [2] a1 5b [2] a3 5a [2] b8 5c [2] a4 5b [2] b8 74 }

  condition:
    any of them
}