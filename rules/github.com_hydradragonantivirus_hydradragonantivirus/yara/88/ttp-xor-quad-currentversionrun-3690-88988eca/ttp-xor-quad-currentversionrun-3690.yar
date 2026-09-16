rule TTP_XOR_QUAD_CurrentVersionRun_3690 {
  strings:
    $key_3690 = { 65 ff [2] 41 f1 [2] 6a dd [2] 44 ff [2] 50 e4 [2] 5f fe [2] 41 e3 [2] 43 e2 [2] 58 e4 [2] 44 e3 [2] 58 cc }

  condition:
    any of them
}