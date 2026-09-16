rule TTP_XOR_QUAD_CurrentVersionRun_7d90 {
  strings:
    $key_7d90 = { 2e ff [2] 0a f1 [2] 21 dd [2] 0f ff [2] 1b e4 [2] 14 fe [2] 0a e3 [2] 08 e2 [2] 13 e4 [2] 0f e3 [2] 13 cc }

  condition:
    any of them
}