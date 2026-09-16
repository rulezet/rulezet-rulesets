rule TTP_XOR_QUAD_CurrentVersionRun_d08d {
  strings:
    $key_d08d = { 83 e2 [2] a7 ec [2] 8c c0 [2] a2 e2 [2] b6 f9 [2] b9 e3 [2] a7 fe [2] a5 ff [2] be f9 [2] a2 fe [2] be d1 }

  condition:
    any of them
}