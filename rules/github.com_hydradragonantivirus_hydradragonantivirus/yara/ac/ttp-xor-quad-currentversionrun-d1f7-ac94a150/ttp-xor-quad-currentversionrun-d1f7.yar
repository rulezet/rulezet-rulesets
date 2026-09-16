rule TTP_XOR_QUAD_CurrentVersionRun_d1f7 {
  strings:
    $key_d1f7 = { 82 98 [2] a6 96 [2] 8d ba [2] a3 98 [2] b7 83 [2] b8 99 [2] a6 84 [2] a4 85 [2] bf 83 [2] a3 84 [2] bf ab }

  condition:
    any of them
}