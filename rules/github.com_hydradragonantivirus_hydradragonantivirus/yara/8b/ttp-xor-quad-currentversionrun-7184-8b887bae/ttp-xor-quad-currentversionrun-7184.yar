rule TTP_XOR_QUAD_CurrentVersionRun_7184 {
  strings:
    $key_7184 = { 22 eb [2] 06 e5 [2] 2d c9 [2] 03 eb [2] 17 f0 [2] 18 ea [2] 06 f7 [2] 04 f6 [2] 1f f0 [2] 03 f7 [2] 1f d8 }

  condition:
    any of them
}