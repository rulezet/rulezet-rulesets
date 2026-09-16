rule TTP_XOR_QUAD_CurrentVersionRun_509f {
  strings:
    $key_509f = { 03 f0 [2] 27 fe [2] 0c d2 [2] 22 f0 [2] 36 eb [2] 39 f1 [2] 27 ec [2] 25 ed [2] 3e eb [2] 22 ec [2] 3e c3 }

  condition:
    any of them
}