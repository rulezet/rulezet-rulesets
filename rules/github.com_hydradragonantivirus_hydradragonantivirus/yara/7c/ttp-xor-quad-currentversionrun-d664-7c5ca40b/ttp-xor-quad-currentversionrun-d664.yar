rule TTP_XOR_QUAD_CurrentVersionRun_d664 {
  strings:
    $key_d664 = { 85 0b [2] a1 05 [2] 8a 29 [2] a4 0b [2] b0 10 [2] bf 0a [2] a1 17 [2] a3 16 [2] b8 10 [2] a4 17 [2] b8 38 }

  condition:
    any of them
}