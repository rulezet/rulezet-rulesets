rule TTP_XOR_QUAD_CurrentVersionRun_719f {
  strings:
    $key_719f = { 22 f0 [2] 06 fe [2] 2d d2 [2] 03 f0 [2] 17 eb [2] 18 f1 [2] 06 ec [2] 04 ed [2] 1f eb [2] 03 ec [2] 1f c3 }

  condition:
    any of them
}