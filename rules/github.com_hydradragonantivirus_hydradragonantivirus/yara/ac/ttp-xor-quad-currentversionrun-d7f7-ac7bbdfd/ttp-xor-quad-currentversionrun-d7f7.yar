rule TTP_XOR_QUAD_CurrentVersionRun_d7f7 {
  strings:
    $key_d7f7 = { 84 98 [2] a0 96 [2] 8b ba [2] a5 98 [2] b1 83 [2] be 99 [2] a0 84 [2] a2 85 [2] b9 83 [2] a5 84 [2] b9 ab }

  condition:
    any of them
}