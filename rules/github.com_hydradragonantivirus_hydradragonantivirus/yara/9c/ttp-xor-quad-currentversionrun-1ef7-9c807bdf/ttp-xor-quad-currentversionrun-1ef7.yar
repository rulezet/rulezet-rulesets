rule TTP_XOR_QUAD_CurrentVersionRun_1ef7 {
  strings:
    $key_1ef7 = { 4d 98 [2] 69 96 [2] 42 ba [2] 6c 98 [2] 78 83 [2] 77 99 [2] 69 84 [2] 6b 85 [2] 70 83 [2] 6c 84 [2] 70 ab }

  condition:
    any of them
}