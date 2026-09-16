rule TTP_XOR_QUAD_CurrentVersionRun_65f7 {
  strings:
    $key_65f7 = { 36 98 [2] 12 96 [2] 39 ba [2] 17 98 [2] 03 83 [2] 0c 99 [2] 12 84 [2] 10 85 [2] 0b 83 [2] 17 84 [2] 0b ab }

  condition:
    any of them
}