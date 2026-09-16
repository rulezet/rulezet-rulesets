rule TTP_XOR_QUAD_CurrentVersionRun_518c {
  strings:
    $key_518c = { 02 e3 [2] 26 ed [2] 0d c1 [2] 23 e3 [2] 37 f8 [2] 38 e2 [2] 26 ff [2] 24 fe [2] 3f f8 [2] 23 ff [2] 3f d0 }

  condition:
    any of them
}