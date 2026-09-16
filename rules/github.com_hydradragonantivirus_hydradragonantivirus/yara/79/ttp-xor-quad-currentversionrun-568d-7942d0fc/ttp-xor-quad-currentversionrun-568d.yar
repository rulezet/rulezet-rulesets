rule TTP_XOR_QUAD_CurrentVersionRun_568d {
  strings:
    $key_568d = { 05 e2 [2] 21 ec [2] 0a c0 [2] 24 e2 [2] 30 f9 [2] 3f e3 [2] 21 fe [2] 23 ff [2] 38 f9 [2] 24 fe [2] 38 d1 }

  condition:
    any of them
}