rule TTP_XOR_QUAD_CurrentVersionRun_31b3 {
  strings:
    $key_31b3 = { 62 dc [2] 46 d2 [2] 6d fe [2] 43 dc [2] 57 c7 [2] 58 dd [2] 46 c0 [2] 44 c1 [2] 5f c7 [2] 43 c0 [2] 5f ef }

  condition:
    any of them
}