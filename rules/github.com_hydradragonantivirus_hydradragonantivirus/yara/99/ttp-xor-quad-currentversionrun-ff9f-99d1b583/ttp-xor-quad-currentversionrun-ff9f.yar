rule TTP_XOR_QUAD_CurrentVersionRun_ff9f {
  strings:
    $key_ff9f = { ac f0 [2] 88 fe [2] a3 d2 [2] 8d f0 [2] 99 eb [2] 96 f1 [2] 88 ec [2] 8a ed [2] 91 eb [2] 8d ec [2] 91 c3 }

  condition:
    any of them
}