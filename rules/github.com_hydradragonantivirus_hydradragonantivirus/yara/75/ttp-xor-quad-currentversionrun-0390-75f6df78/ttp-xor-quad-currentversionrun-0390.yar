rule TTP_XOR_QUAD_CurrentVersionRun_0390 {
  strings:
    $key_0390 = { 50 ff [2] 74 f1 [2] 5f dd [2] 71 ff [2] 65 e4 [2] 6a fe [2] 74 e3 [2] 76 e2 [2] 6d e4 [2] 71 e3 [2] 6d cc }

  condition:
    any of them
}