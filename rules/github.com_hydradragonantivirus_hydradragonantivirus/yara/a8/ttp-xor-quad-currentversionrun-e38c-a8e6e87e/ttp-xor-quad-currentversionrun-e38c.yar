rule TTP_XOR_QUAD_CurrentVersionRun_e38c {
  strings:
    $key_e38c = { b0 e3 [2] 94 ed [2] bf c1 [2] 91 e3 [2] 85 f8 [2] 8a e2 [2] 94 ff [2] 96 fe [2] 8d f8 [2] 91 ff [2] 8d d0 }

  condition:
    any of them
}