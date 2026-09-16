rule TTP_XOR_QUAD_CurrentVersionRun_119f {
  strings:
    $key_119f = { 42 f0 [2] 66 fe [2] 4d d2 [2] 63 f0 [2] 77 eb [2] 78 f1 [2] 66 ec [2] 64 ed [2] 7f eb [2] 63 ec [2] 7f c3 }

  condition:
    any of them
}