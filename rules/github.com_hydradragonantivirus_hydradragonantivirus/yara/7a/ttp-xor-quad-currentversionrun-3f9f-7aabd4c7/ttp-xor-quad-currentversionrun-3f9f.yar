rule TTP_XOR_QUAD_CurrentVersionRun_3f9f {
  strings:
    $key_3f9f = { 6c f0 [2] 48 fe [2] 63 d2 [2] 4d f0 [2] 59 eb [2] 56 f1 [2] 48 ec [2] 4a ed [2] 51 eb [2] 4d ec [2] 51 c3 }

  condition:
    any of them
}