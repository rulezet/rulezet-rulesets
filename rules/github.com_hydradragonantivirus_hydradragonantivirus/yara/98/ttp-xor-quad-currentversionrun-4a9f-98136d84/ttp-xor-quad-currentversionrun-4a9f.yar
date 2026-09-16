rule TTP_XOR_QUAD_CurrentVersionRun_4a9f {
  strings:
    $key_4a9f = { 19 f0 [2] 3d fe [2] 16 d2 [2] 38 f0 [2] 2c eb [2] 23 f1 [2] 3d ec [2] 3f ed [2] 24 eb [2] 38 ec [2] 24 c3 }

  condition:
    any of them
}