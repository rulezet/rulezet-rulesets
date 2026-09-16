rule TTP_XOR_QUAD_CurrentVersionRun_c7f7 {
  strings:
    $key_c7f7 = { 94 98 [2] b0 96 [2] 9b ba [2] b5 98 [2] a1 83 [2] ae 99 [2] b0 84 [2] b2 85 [2] a9 83 [2] b5 84 [2] a9 ab }

  condition:
    any of them
}