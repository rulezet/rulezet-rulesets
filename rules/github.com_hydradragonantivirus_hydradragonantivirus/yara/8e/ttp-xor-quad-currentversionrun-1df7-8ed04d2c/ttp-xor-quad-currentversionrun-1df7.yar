rule TTP_XOR_QUAD_CurrentVersionRun_1df7 {
  strings:
    $key_1df7 = { 4e 98 [2] 6a 96 [2] 41 ba [2] 6f 98 [2] 7b 83 [2] 74 99 [2] 6a 84 [2] 68 85 [2] 73 83 [2] 6f 84 [2] 73 ab }

  condition:
    any of them
}