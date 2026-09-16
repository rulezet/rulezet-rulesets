rule TTP_XOR_QUAD_CurrentVersionRun_348b {
  strings:
    $key_348b = { 67 e4 [2] 43 ea [2] 68 c6 [2] 46 e4 [2] 52 ff [2] 5d e5 [2] 43 f8 [2] 41 f9 [2] 5a ff [2] 46 f8 [2] 5a d7 }

  condition:
    any of them
}