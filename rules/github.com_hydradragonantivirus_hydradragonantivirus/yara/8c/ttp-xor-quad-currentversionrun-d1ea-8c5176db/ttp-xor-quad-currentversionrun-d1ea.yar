rule TTP_XOR_QUAD_CurrentVersionRun_d1ea {
  strings:
    $key_d1ea = { 82 85 [2] a6 8b [2] 8d a7 [2] a3 85 [2] b7 9e [2] b8 84 [2] a6 99 [2] a4 98 [2] bf 9e [2] a3 99 [2] bf b6 }

  condition:
    any of them
}