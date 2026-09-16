rule TTP_XOR_QUAD_CurrentVersionRun_40b3 {
  strings:
    $key_40b3 = { 13 dc [2] 37 d2 [2] 1c fe [2] 32 dc [2] 26 c7 [2] 29 dd [2] 37 c0 [2] 35 c1 [2] 2e c7 [2] 32 c0 [2] 2e ef }

  condition:
    any of them
}