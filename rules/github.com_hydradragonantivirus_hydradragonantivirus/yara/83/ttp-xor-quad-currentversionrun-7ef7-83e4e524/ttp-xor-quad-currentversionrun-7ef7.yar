rule TTP_XOR_QUAD_CurrentVersionRun_7ef7 {
  strings:
    $key_7ef7 = { 2d 98 [2] 09 96 [2] 22 ba [2] 0c 98 [2] 18 83 [2] 17 99 [2] 09 84 [2] 0b 85 [2] 10 83 [2] 0c 84 [2] 10 ab }

  condition:
    any of them
}