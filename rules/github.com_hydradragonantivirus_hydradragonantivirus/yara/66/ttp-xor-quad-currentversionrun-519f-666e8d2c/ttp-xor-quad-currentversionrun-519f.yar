rule TTP_XOR_QUAD_CurrentVersionRun_519f {
  strings:
    $key_519f = { 02 f0 [2] 26 fe [2] 0d d2 [2] 23 f0 [2] 37 eb [2] 38 f1 [2] 26 ec [2] 24 ed [2] 3f eb [2] 23 ec [2] 3f c3 }

  condition:
    any of them
}