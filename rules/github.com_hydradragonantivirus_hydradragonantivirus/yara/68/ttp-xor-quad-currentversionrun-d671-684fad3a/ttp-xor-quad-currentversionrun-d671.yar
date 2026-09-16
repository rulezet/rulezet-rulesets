rule TTP_XOR_QUAD_CurrentVersionRun_d671 {
  strings:
    $key_d671 = { 85 1e [2] a1 10 [2] 8a 3c [2] a4 1e [2] b0 05 [2] bf 1f [2] a1 02 [2] a3 03 [2] b8 05 [2] a4 02 [2] b8 2d }

  condition:
    any of them
}