rule TTP_XOR_QUAD_CurrentVersionRun_2d90 {
  strings:
    $key_2d90 = { 7e ff [2] 5a f1 [2] 71 dd [2] 5f ff [2] 4b e4 [2] 44 fe [2] 5a e3 [2] 58 e2 [2] 43 e4 [2] 5f e3 [2] 43 cc }

  condition:
    any of them
}