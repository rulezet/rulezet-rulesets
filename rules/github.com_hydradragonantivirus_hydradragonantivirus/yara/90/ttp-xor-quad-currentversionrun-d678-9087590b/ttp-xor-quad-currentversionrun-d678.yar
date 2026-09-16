rule TTP_XOR_QUAD_CurrentVersionRun_d678 {
  strings:
    $key_d678 = { 85 17 [2] a1 19 [2] 8a 35 [2] a4 17 [2] b0 0c [2] bf 16 [2] a1 0b [2] a3 0a [2] b8 0c [2] a4 0b [2] b8 24 }

  condition:
    any of them
}