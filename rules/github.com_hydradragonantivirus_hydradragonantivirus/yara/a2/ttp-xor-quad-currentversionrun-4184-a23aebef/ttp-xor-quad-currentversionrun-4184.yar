rule TTP_XOR_QUAD_CurrentVersionRun_4184 {
  strings:
    $key_4184 = { 12 eb [2] 36 e5 [2] 1d c9 [2] 33 eb [2] 27 f0 [2] 28 ea [2] 36 f7 [2] 34 f6 [2] 2f f0 [2] 33 f7 [2] 2f d8 }

  condition:
    any of them
}