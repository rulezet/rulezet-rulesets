rule TTP_XOR_QUAD_CurrentVersionRun_2590 {
  strings:
    $key_2590 = { 76 ff [2] 52 f1 [2] 79 dd [2] 57 ff [2] 43 e4 [2] 4c fe [2] 52 e3 [2] 50 e2 [2] 4b e4 [2] 57 e3 [2] 4b cc }

  condition:
    any of them
}