rule TTP_XOR_QUAD_CurrentVersionRun_6390 {
  strings:
    $key_6390 = { 30 ff [2] 14 f1 [2] 3f dd [2] 11 ff [2] 05 e4 [2] 0a fe [2] 14 e3 [2] 16 e2 [2] 0d e4 [2] 11 e3 [2] 0d cc }

  condition:
    any of them
}