rule TTP_XOR_QUAD_CurrentVersionRun_3084 {
  strings:
    $key_3084 = { 63 eb [2] 47 e5 [2] 6c c9 [2] 42 eb [2] 56 f0 [2] 59 ea [2] 47 f7 [2] 45 f6 [2] 5e f0 [2] 42 f7 [2] 5e d8 }

  condition:
    any of them
}