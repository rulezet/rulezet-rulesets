rule TTP_XOR_QUAD_CurrentVersionRun_d66a {
  strings:
    $key_d66a = { 85 05 [2] a1 0b [2] 8a 27 [2] a4 05 [2] b0 1e [2] bf 04 [2] a1 19 [2] a3 18 [2] b8 1e [2] a4 19 [2] b8 36 }

  condition:
    any of them
}