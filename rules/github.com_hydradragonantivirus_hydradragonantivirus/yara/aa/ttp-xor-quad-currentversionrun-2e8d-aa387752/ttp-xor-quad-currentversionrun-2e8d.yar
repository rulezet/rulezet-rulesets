rule TTP_XOR_QUAD_CurrentVersionRun_2e8d {
  strings:
    $key_2e8d = { 7d e2 [2] 59 ec [2] 72 c0 [2] 5c e2 [2] 48 f9 [2] 47 e3 [2] 59 fe [2] 5b ff [2] 40 f9 [2] 5c fe [2] 40 d1 }

  condition:
    any of them
}