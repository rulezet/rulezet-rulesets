rule TTP_XOR_QUAD_CurrentVersionRun_009f {
  strings:
    $key_009f = { 53 f0 [2] 77 fe [2] 5c d2 [2] 72 f0 [2] 66 eb [2] 69 f1 [2] 77 ec [2] 75 ed [2] 6e eb [2] 72 ec [2] 6e c3 }

  condition:
    any of them
}