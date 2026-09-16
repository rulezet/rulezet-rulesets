rule TTP_XOR_QUAD_CurrentVersionRun_6690 {
  strings:
    $key_6690 = { 35 ff [2] 11 f1 [2] 3a dd [2] 14 ff [2] 00 e4 [2] 0f fe [2] 11 e3 [2] 13 e2 [2] 08 e4 [2] 14 e3 [2] 08 cc }

  condition:
    any of them
}