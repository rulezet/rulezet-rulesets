rule TTP_XOR_QUAD_CurrentVersionRun_1184 {
  strings:
    $key_1184 = { 42 eb [2] 66 e5 [2] 4d c9 [2] 63 eb [2] 77 f0 [2] 78 ea [2] 66 f7 [2] 64 f6 [2] 7f f0 [2] 63 f7 [2] 7f d8 }

  condition:
    any of them
}