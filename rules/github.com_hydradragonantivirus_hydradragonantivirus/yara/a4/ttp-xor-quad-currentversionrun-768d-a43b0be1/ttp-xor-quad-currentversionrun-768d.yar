rule TTP_XOR_QUAD_CurrentVersionRun_768d {
  strings:
    $key_768d = { 25 e2 [2] 01 ec [2] 2a c0 [2] 04 e2 [2] 10 f9 [2] 1f e3 [2] 01 fe [2] 03 ff [2] 18 f9 [2] 04 fe [2] 18 d1 }

  condition:
    any of them
}