rule TTP_XOR_QUAD_CurrentVersionRun_218d {
  strings:
    $key_218d = { 72 e2 [2] 56 ec [2] 7d c0 [2] 53 e2 [2] 47 f9 [2] 48 e3 [2] 56 fe [2] 54 ff [2] 4f f9 [2] 53 fe [2] 4f d1 }

  condition:
    any of them
}