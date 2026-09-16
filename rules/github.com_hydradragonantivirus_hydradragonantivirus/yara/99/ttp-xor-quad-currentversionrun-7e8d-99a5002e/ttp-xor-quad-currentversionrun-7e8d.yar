rule TTP_XOR_QUAD_CurrentVersionRun_7e8d {
  strings:
    $key_7e8d = { 2d e2 [2] 09 ec [2] 22 c0 [2] 0c e2 [2] 18 f9 [2] 17 e3 [2] 09 fe [2] 0b ff [2] 10 f9 [2] 0c fe [2] 10 d1 }

  condition:
    any of them
}