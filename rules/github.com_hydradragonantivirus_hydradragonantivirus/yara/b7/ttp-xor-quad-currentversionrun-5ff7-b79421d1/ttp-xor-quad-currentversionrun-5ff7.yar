rule TTP_XOR_QUAD_CurrentVersionRun_5ff7 {
  strings:
    $key_5ff7 = { 0c 98 [2] 28 96 [2] 03 ba [2] 2d 98 [2] 39 83 [2] 36 99 [2] 28 84 [2] 2a 85 [2] 31 83 [2] 2d 84 [2] 31 ab }

  condition:
    any of them
}