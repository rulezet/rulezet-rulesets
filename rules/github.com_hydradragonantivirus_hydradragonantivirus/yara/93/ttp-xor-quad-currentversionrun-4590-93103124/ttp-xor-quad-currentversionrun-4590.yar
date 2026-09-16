rule TTP_XOR_QUAD_CurrentVersionRun_4590 {
  strings:
    $key_4590 = { 16 ff [2] 32 f1 [2] 19 dd [2] 37 ff [2] 23 e4 [2] 2c fe [2] 32 e3 [2] 30 e2 [2] 2b e4 [2] 37 e3 [2] 2b cc }

  condition:
    any of them
}