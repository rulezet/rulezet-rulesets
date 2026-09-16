rule TTP_XOR_QUAD_CurrentVersionRun_63f7 {
  strings:
    $key_63f7 = { 30 98 [2] 14 96 [2] 3f ba [2] 11 98 [2] 05 83 [2] 0a 99 [2] 14 84 [2] 16 85 [2] 0d 83 [2] 11 84 [2] 0d ab }

  condition:
    any of them
}