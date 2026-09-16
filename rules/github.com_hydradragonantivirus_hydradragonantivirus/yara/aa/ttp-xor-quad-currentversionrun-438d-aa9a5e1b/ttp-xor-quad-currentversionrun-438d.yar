rule TTP_XOR_QUAD_CurrentVersionRun_438d {
  strings:
    $key_438d = { 10 e2 [2] 34 ec [2] 1f c0 [2] 31 e2 [2] 25 f9 [2] 2a e3 [2] 34 fe [2] 36 ff [2] 2d f9 [2] 31 fe [2] 2d d1 }

  condition:
    any of them
}