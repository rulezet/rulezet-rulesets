rule TTP_XOR_QUAD_CurrentVersionRun_0c90 {
  strings:
    $key_0c90 = { 5f ff [2] 7b f1 [2] 50 dd [2] 7e ff [2] 6a e4 [2] 65 fe [2] 7b e3 [2] 79 e2 [2] 62 e4 [2] 7e e3 [2] 62 cc }

  condition:
    any of them
}