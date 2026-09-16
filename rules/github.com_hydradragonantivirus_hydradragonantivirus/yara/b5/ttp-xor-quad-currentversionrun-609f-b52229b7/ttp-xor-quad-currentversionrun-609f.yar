rule TTP_XOR_QUAD_CurrentVersionRun_609f {
  strings:
    $key_609f = { 33 f0 [2] 17 fe [2] 3c d2 [2] 12 f0 [2] 06 eb [2] 09 f1 [2] 17 ec [2] 15 ed [2] 0e eb [2] 12 ec [2] 0e c3 }

  condition:
    any of them
}