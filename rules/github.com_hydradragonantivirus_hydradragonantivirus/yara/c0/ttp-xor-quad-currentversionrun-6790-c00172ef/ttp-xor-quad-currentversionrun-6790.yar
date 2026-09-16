rule TTP_XOR_QUAD_CurrentVersionRun_6790 {
  strings:
    $key_6790 = { 34 ff [2] 10 f1 [2] 3b dd [2] 15 ff [2] 01 e4 [2] 0e fe [2] 10 e3 [2] 12 e2 [2] 09 e4 [2] 15 e3 [2] 09 cc }

  condition:
    any of them
}