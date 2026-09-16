rule TTP_XOR_QUAD_CurrentVersionRun_1690 {
  strings:
    $key_1690 = { 45 ff [2] 61 f1 [2] 4a dd [2] 64 ff [2] 70 e4 [2] 7f fe [2] 61 e3 [2] 63 e2 [2] 78 e4 [2] 64 e3 [2] 78 cc }

  condition:
    any of them
}