rule TTP_XOR_QUAD_CurrentVersionRun_018d {
  strings:
    $key_018d = { 52 e2 [2] 76 ec [2] 5d c0 [2] 73 e2 [2] 67 f9 [2] 68 e3 [2] 76 fe [2] 74 ff [2] 6f f9 [2] 73 fe [2] 6f d1 }

  condition:
    any of them
}