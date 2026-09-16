rule TTP_XOR_QUAD_CurrentVersionRun_4ef7 {
  strings:
    $key_4ef7 = { 1d 98 [2] 39 96 [2] 12 ba [2] 3c 98 [2] 28 83 [2] 27 99 [2] 39 84 [2] 3b 85 [2] 20 83 [2] 3c 84 [2] 20 ab }

  condition:
    any of them
}