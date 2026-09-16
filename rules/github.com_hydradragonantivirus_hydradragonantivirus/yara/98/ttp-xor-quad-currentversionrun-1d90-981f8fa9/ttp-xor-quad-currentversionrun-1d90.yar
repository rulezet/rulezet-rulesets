rule TTP_XOR_QUAD_CurrentVersionRun_1d90 {
  strings:
    $key_1d90 = { 4e ff [2] 6a f1 [2] 41 dd [2] 6f ff [2] 7b e4 [2] 74 fe [2] 6a e3 [2] 68 e2 [2] 73 e4 [2] 6f e3 [2] 73 cc }

  condition:
    any of them
}