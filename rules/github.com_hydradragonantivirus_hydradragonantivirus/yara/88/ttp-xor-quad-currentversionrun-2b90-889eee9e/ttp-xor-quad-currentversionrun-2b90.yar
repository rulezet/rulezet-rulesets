rule TTP_XOR_QUAD_CurrentVersionRun_2b90 {
  strings:
    $key_2b90 = { 78 ff [2] 5c f1 [2] 77 dd [2] 59 ff [2] 4d e4 [2] 42 fe [2] 5c e3 [2] 5e e2 [2] 45 e4 [2] 59 e3 [2] 45 cc }

  condition:
    any of them
}