rule TTP_XOR_QUAD_CurrentVersionRun_3190 {
  strings:
    $key_3190 = { 62 ff [2] 46 f1 [2] 6d dd [2] 43 ff [2] 57 e4 [2] 58 fe [2] 46 e3 [2] 44 e2 [2] 5f e4 [2] 43 e3 [2] 5f cc }

  condition:
    any of them
}