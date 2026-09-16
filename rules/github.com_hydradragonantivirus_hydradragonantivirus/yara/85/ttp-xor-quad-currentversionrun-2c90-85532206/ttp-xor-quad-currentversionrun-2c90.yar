rule TTP_XOR_QUAD_CurrentVersionRun_2c90 {
  strings:
    $key_2c90 = { 7f ff [2] 5b f1 [2] 70 dd [2] 5e ff [2] 4a e4 [2] 45 fe [2] 5b e3 [2] 59 e2 [2] 42 e4 [2] 5e e3 [2] 42 cc }

  condition:
    any of them
}