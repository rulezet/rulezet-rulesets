rule TTP_XOR_QUAD_CurrentVersionRun_c08d {
  strings:
    $key_c08d = { 93 e2 [2] b7 ec [2] 9c c0 [2] b2 e2 [2] a6 f9 [2] a9 e3 [2] b7 fe [2] b5 ff [2] ae f9 [2] b2 fe [2] ae d1 }

  condition:
    any of them
}