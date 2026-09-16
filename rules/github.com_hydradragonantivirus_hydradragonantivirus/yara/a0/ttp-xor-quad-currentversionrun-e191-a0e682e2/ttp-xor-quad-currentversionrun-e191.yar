rule TTP_XOR_QUAD_CurrentVersionRun_e191 {
  strings:
    $key_e191 = { b2 fe [2] 96 f0 [2] bd dc [2] 93 fe [2] 87 e5 [2] 88 ff [2] 96 e2 [2] 94 e3 [2] 8f e5 [2] 93 e2 [2] 8f cd }

  condition:
    any of them
}