rule TTP_XOR_QUAD_CurrentVersionRun_f2f7 {
  strings:
    $key_f2f7 = { a1 98 [2] 85 96 [2] ae ba [2] 80 98 [2] 94 83 [2] 9b 99 [2] 85 84 [2] 87 85 [2] 9c 83 [2] 80 84 [2] 9c ab }

  condition:
    any of them
}