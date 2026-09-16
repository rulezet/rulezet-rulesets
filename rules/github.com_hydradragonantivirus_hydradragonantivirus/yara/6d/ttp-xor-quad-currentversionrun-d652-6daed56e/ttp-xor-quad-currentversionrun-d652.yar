rule TTP_XOR_QUAD_CurrentVersionRun_d652 {
  strings:
    $key_d652 = { 85 3d [2] a1 33 [2] 8a 1f [2] a4 3d [2] b0 26 [2] bf 3c [2] a1 21 [2] a3 20 [2] b8 26 [2] a4 21 [2] b8 0e }

  condition:
    any of them
}