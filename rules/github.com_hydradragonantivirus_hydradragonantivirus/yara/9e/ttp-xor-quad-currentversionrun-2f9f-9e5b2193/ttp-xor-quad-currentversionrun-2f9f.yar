rule TTP_XOR_QUAD_CurrentVersionRun_2f9f {
  strings:
    $key_2f9f = { 7c f0 [2] 58 fe [2] 73 d2 [2] 5d f0 [2] 49 eb [2] 46 f1 [2] 58 ec [2] 5a ed [2] 41 eb [2] 5d ec [2] 41 c3 }

  condition:
    any of them
}