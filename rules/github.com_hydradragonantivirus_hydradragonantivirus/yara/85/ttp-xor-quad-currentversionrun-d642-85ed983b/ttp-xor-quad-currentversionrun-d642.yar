rule TTP_XOR_QUAD_CurrentVersionRun_d642 {
  strings:
    $key_d642 = { 85 2d [2] a1 23 [2] 8a 0f [2] a4 2d [2] b0 36 [2] bf 2c [2] a1 31 [2] a3 30 [2] b8 36 [2] a4 31 [2] b8 1e }

  condition:
    any of them
}