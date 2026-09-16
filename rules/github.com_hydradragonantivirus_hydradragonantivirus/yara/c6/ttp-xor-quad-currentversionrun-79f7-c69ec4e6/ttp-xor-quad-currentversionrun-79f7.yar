rule TTP_XOR_QUAD_CurrentVersionRun_79f7 {
  strings:
    $key_79f7 = { 2a 98 [2] 0e 96 [2] 25 ba [2] 0b 98 [2] 1f 83 [2] 10 99 [2] 0e 84 [2] 0c 85 [2] 17 83 [2] 0b 84 [2] 17 ab }

  condition:
    any of them
}