rule TTP_XOR_QUAD_CurrentVersionRun_e38d {
  strings:
    $key_e38d = { b0 e2 [2] 94 ec [2] bf c0 [2] 91 e2 [2] 85 f9 [2] 8a e3 [2] 94 fe [2] 96 ff [2] 8d f9 [2] 91 fe [2] 8d d1 }

  condition:
    any of them
}