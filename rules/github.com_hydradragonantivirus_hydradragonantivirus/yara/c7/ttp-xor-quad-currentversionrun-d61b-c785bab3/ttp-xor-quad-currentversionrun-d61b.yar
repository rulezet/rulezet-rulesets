rule TTP_XOR_QUAD_CurrentVersionRun_d61b {
  strings:
    $key_d61b = { 85 74 [2] a1 7a [2] 8a 56 [2] a4 74 [2] b0 6f [2] bf 75 [2] a1 68 [2] a3 69 [2] b8 6f [2] a4 68 [2] b8 47 }

  condition:
    any of them
}