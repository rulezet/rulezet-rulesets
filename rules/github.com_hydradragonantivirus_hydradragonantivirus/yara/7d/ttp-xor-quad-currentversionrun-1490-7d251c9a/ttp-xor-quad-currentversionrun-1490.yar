rule TTP_XOR_QUAD_CurrentVersionRun_1490 {
  strings:
    $key_1490 = { 47 ff [2] 63 f1 [2] 48 dd [2] 66 ff [2] 72 e4 [2] 7d fe [2] 63 e3 [2] 61 e2 [2] 7a e4 [2] 66 e3 [2] 7a cc }

  condition:
    any of them
}