rule TTP_XOR_QUAD_CurrentVersionRun_7ff7 {
  strings:
    $key_7ff7 = { 2c 98 [2] 08 96 [2] 23 ba [2] 0d 98 [2] 19 83 [2] 16 99 [2] 08 84 [2] 0a 85 [2] 11 83 [2] 0d 84 [2] 11 ab }

  condition:
    any of them
}