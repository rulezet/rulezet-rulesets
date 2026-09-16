rule TTP_XOR_QUAD_CurrentVersionRun_01b3 {
  strings:
    $key_01b3 = { 52 dc [2] 76 d2 [2] 5d fe [2] 73 dc [2] 67 c7 [2] 68 dd [2] 76 c0 [2] 74 c1 [2] 6f c7 [2] 73 c0 [2] 6f ef }

  condition:
    any of them
}