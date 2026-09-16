rule TTP_XOR_QUAD_CurrentVersionRun_468d {
  strings:
    $key_468d = { 15 e2 [2] 31 ec [2] 1a c0 [2] 34 e2 [2] 20 f9 [2] 2f e3 [2] 31 fe [2] 33 ff [2] 28 f9 [2] 34 fe [2] 28 d1 }

  condition:
    any of them
}