rule TTP_XOR_QUAD_CurrentVersionRun_718c {
  strings:
    $key_718c = { 22 e3 [2] 06 ed [2] 2d c1 [2] 03 e3 [2] 17 f8 [2] 18 e2 [2] 06 ff [2] 04 fe [2] 1f f8 [2] 03 ff [2] 1f d0 }

  condition:
    any of them
}