rule TTP_XOR_QUAD_CurrentVersionRun_679f {
  strings:
    $key_679f = { 34 f0 [2] 10 fe [2] 3b d2 [2] 15 f0 [2] 01 eb [2] 0e f1 [2] 10 ec [2] 12 ed [2] 09 eb [2] 15 ec [2] 09 c3 }

  condition:
    any of them
}