rule TTP_XOR_QUAD_CurrentVersionRun_10b3 {
  strings:
    $key_10b3 = { 43 dc [2] 67 d2 [2] 4c fe [2] 62 dc [2] 76 c7 [2] 79 dd [2] 67 c0 [2] 65 c1 [2] 7e c7 [2] 62 c0 [2] 7e ef }

  condition:
    any of them
}