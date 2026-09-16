rule TTP_XOR_QUAD_CurrentVersionRun_d665 {
  strings:
    $key_d665 = { 85 0a [2] a1 04 [2] 8a 28 [2] a4 0a [2] b0 11 [2] bf 0b [2] a1 16 [2] a3 17 [2] b8 11 [2] a4 16 [2] b8 39 }

  condition:
    any of them
}