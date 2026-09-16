rule TTP_XOR_QUAD_CurrentVersionRun_1590 {
  strings:
    $key_1590 = { 46 ff [2] 62 f1 [2] 49 dd [2] 67 ff [2] 73 e4 [2] 7c fe [2] 62 e3 [2] 60 e2 [2] 7b e4 [2] 67 e3 [2] 7b cc }

  condition:
    any of them
}