rule TTP_XOR_QUAD_CurrentVersionRun_0690 {
  strings:
    $key_0690 = { 55 ff [2] 71 f1 [2] 5a dd [2] 74 ff [2] 60 e4 [2] 6f fe [2] 71 e3 [2] 73 e2 [2] 68 e4 [2] 74 e3 [2] 68 cc }

  condition:
    any of them
}