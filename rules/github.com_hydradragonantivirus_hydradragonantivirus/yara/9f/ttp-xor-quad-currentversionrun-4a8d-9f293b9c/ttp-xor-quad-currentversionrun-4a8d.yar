rule TTP_XOR_QUAD_CurrentVersionRun_4a8d {
  strings:
    $key_4a8d = { 19 e2 [2] 3d ec [2] 16 c0 [2] 38 e2 [2] 2c f9 [2] 23 e3 [2] 3d fe [2] 3f ff [2] 24 f9 [2] 38 fe [2] 24 d1 }

  condition:
    any of them
}