rule TTP_XOR_QUAD_CurrentVersionRun_5d90 {
  strings:
    $key_5d90 = { 0e ff [2] 2a f1 [2] 01 dd [2] 2f ff [2] 3b e4 [2] 34 fe [2] 2a e3 [2] 28 e2 [2] 33 e4 [2] 2f e3 [2] 33 cc }

  condition:
    any of them
}