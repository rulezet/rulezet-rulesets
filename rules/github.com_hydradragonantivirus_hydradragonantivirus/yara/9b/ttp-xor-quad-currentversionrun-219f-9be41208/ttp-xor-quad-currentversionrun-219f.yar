rule TTP_XOR_QUAD_CurrentVersionRun_219f {
  strings:
    $key_219f = { 72 f0 [2] 56 fe [2] 7d d2 [2] 53 f0 [2] 47 eb [2] 48 f1 [2] 56 ec [2] 54 ed [2] 4f eb [2] 53 ec [2] 4f c3 }

  condition:
    any of them
}