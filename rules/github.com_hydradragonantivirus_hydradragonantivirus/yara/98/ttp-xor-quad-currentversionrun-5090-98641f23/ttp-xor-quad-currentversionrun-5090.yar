rule TTP_XOR_QUAD_CurrentVersionRun_5090 {
  strings:
    $key_5090 = { 03 ff [2] 27 f1 [2] 0c dd [2] 22 ff [2] 36 e4 [2] 39 fe [2] 27 e3 [2] 25 e2 [2] 3e e4 [2] 22 e3 [2] 3e cc }

  condition:
    any of them
}