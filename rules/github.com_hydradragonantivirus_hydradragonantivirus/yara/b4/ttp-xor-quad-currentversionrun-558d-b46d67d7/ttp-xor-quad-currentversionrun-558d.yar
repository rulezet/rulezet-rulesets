rule TTP_XOR_QUAD_CurrentVersionRun_558d {
  strings:
    $key_558d = { 06 e2 [2] 22 ec [2] 09 c0 [2] 27 e2 [2] 33 f9 [2] 3c e3 [2] 22 fe [2] 20 ff [2] 3b f9 [2] 27 fe [2] 3b d1 }

  condition:
    any of them
}