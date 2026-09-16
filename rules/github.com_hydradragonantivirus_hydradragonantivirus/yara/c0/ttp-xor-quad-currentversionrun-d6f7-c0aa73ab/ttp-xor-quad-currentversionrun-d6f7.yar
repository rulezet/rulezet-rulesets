rule TTP_XOR_QUAD_CurrentVersionRun_d6f7 {
  strings:
    $key_d6f7 = { 85 98 [2] a1 96 [2] 8a ba [2] a4 98 [2] b0 83 [2] bf 99 [2] a1 84 [2] a3 85 [2] b8 83 [2] a4 84 [2] b8 ab }

  condition:
    any of them
}