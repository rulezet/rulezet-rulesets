rule TTP_XOR_QUAD_CurrentVersionRun_7490 {
  strings:
    $key_7490 = { 27 ff [2] 03 f1 [2] 28 dd [2] 06 ff [2] 12 e4 [2] 1d fe [2] 03 e3 [2] 01 e2 [2] 1a e4 [2] 06 e3 [2] 1a cc }

  condition:
    any of them
}