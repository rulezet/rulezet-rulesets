rule TTP_XOR_QUAD_CurrentVersionRun_57f7 {
  strings:
    $key_57f7 = { 04 98 [2] 20 96 [2] 0b ba [2] 25 98 [2] 31 83 [2] 3e 99 [2] 20 84 [2] 22 85 [2] 39 83 [2] 25 84 [2] 39 ab }

  condition:
    any of them
}