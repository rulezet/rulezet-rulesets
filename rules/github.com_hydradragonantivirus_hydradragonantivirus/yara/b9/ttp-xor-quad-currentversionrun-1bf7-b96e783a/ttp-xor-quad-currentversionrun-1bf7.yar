rule TTP_XOR_QUAD_CurrentVersionRun_1bf7 {
  strings:
    $key_1bf7 = { 48 98 [2] 6c 96 [2] 47 ba [2] 69 98 [2] 7d 83 [2] 72 99 [2] 6c 84 [2] 6e 85 [2] 75 83 [2] 69 84 [2] 75 ab }

  condition:
    any of them
}