rule TTP_XOR_QUAD_CurrentVersionRun_12b3 {
  strings:
    $key_12b3 = { 41 dc [2] 65 d2 [2] 4e fe [2] 60 dc [2] 74 c7 [2] 7b dd [2] 65 c0 [2] 67 c1 [2] 7c c7 [2] 60 c0 [2] 7c ef }

  condition:
    any of them
}