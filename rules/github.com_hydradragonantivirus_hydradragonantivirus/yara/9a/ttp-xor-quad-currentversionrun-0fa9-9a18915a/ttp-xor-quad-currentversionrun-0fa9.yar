rule TTP_XOR_QUAD_CurrentVersionRun_0fa9 {
  strings:
    $key_0fa9 = { 5c c6 [2] 78 c8 [2] 53 e4 [2] 7d c6 [2] 69 dd [2] 66 c7 [2] 78 da [2] 7a db [2] 61 dd [2] 7d da [2] 61 f5 }

  condition:
    any of them
}