rule TTP_XOR_QUAD_CurrentVersionRun_6a9f {
  strings:
    $key_6a9f = { 39 f0 [2] 1d fe [2] 36 d2 [2] 18 f0 [2] 0c eb [2] 03 f1 [2] 1d ec [2] 1f ed [2] 04 eb [2] 18 ec [2] 04 c3 }

  condition:
    any of them
}