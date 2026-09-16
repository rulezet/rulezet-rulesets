rule TTP_XOR_QUAD_CurrentVersionRun_0a9f {
  strings:
    $key_0a9f = { 59 f0 [2] 7d fe [2] 56 d2 [2] 78 f0 [2] 6c eb [2] 63 f1 [2] 7d ec [2] 7f ed [2] 64 eb [2] 78 ec [2] 64 c3 }

  condition:
    any of them
}