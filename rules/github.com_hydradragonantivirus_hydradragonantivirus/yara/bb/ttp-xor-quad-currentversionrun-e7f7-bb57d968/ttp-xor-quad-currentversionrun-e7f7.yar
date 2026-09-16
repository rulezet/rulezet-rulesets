rule TTP_XOR_QUAD_CurrentVersionRun_e7f7 {
  strings:
    $key_e7f7 = { b4 98 [2] 90 96 [2] bb ba [2] 95 98 [2] 81 83 [2] 8e 99 [2] 90 84 [2] 92 85 [2] 89 83 [2] 95 84 [2] 89 ab }

  condition:
    any of them
}