rule TTP_XOR_QUAD_CurrentVersionRun_2690 {
  strings:
    $key_2690 = { 75 ff [2] 51 f1 [2] 7a dd [2] 54 ff [2] 40 e4 [2] 4f fe [2] 51 e3 [2] 53 e2 [2] 48 e4 [2] 54 e3 [2] 48 cc }

  condition:
    any of them
}