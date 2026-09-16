rule TTP_XOR_QUAD_CurrentVersionRun_348d {
  strings:
    $key_348d = { 67 e2 [2] 43 ec [2] 68 c0 [2] 46 e2 [2] 52 f9 [2] 5d e3 [2] 43 fe [2] 41 ff [2] 5a f9 [2] 46 fe [2] 5a d1 }

  condition:
    any of them
}