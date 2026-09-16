rule TTP_XOR_QUAD_CurrentVersionRun_4690 {
  strings:
    $key_4690 = { 15 ff [2] 31 f1 [2] 1a dd [2] 34 ff [2] 20 e4 [2] 2f fe [2] 31 e3 [2] 33 e2 [2] 28 e4 [2] 34 e3 [2] 28 cc }

  condition:
    any of them
}