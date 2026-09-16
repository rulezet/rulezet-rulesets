rule TTP_XOR_QUAD_CurrentVersionRun_4390 {
  strings:
    $key_4390 = { 10 ff [2] 34 f1 [2] 1f dd [2] 31 ff [2] 25 e4 [2] 2a fe [2] 34 e3 [2] 36 e2 [2] 2d e4 [2] 31 e3 [2] 2d cc }

  condition:
    any of them
}