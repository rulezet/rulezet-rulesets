rule TTP_XOR_QUAD_CurrentVersionRun_5c90 {
  strings:
    $key_5c90 = { 0f ff [2] 2b f1 [2] 00 dd [2] 2e ff [2] 3a e4 [2] 35 fe [2] 2b e3 [2] 29 e2 [2] 32 e4 [2] 2e e3 [2] 32 cc }

  condition:
    any of them
}