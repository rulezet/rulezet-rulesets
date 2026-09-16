rule TTP_XOR_QUAD_CurrentVersionRun_d676 {
  strings:
    $key_d676 = { 85 19 [2] a1 17 [2] 8a 3b [2] a4 19 [2] b0 02 [2] bf 18 [2] a1 05 [2] a3 04 [2] b8 02 [2] a4 05 [2] b8 2a }

  condition:
    any of them
}