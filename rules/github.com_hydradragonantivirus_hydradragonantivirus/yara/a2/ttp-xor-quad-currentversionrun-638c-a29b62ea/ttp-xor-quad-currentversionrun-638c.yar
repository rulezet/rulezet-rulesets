rule TTP_XOR_QUAD_CurrentVersionRun_638c {
  strings:
    $key_638c = { 30 e3 [2] 14 ed [2] 3f c1 [2] 11 e3 [2] 05 f8 [2] 0a e2 [2] 14 ff [2] 16 fe [2] 0d f8 [2] 11 ff [2] 0d d0 }

  condition:
    any of them
}