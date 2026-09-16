rule TTP_XOR_QUAD_CurrentVersionRun_218b {
  strings:
    $key_218b = { 72 e4 [2] 56 ea [2] 7d c6 [2] 53 e4 [2] 47 ff [2] 48 e5 [2] 56 f8 [2] 54 f9 [2] 4f ff [2] 53 f8 [2] 4f d7 }

  condition:
    any of them
}