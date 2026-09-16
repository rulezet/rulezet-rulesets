rule TTP_XOR_QUAD_CurrentVersionRun_6090 {
  strings:
    $key_6090 = { 33 ff [2] 17 f1 [2] 3c dd [2] 12 ff [2] 06 e4 [2] 09 fe [2] 17 e3 [2] 15 e2 [2] 0e e4 [2] 12 e3 [2] 0e cc }

  condition:
    any of them
}