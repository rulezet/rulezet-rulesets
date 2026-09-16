rule TTP_XOR_QUAD_CurrentVersionRun_2cf7 {
  strings:
    $key_2cf7 = { 7f 98 [2] 5b 96 [2] 70 ba [2] 5e 98 [2] 4a 83 [2] 45 99 [2] 5b 84 [2] 59 85 [2] 42 83 [2] 5e 84 [2] 42 ab }

  condition:
    any of them
}