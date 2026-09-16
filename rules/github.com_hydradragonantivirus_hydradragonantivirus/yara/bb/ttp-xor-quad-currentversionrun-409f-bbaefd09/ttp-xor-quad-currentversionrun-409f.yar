rule TTP_XOR_QUAD_CurrentVersionRun_409f {
  strings:
    $key_409f = { 13 f0 [2] 37 fe [2] 1c d2 [2] 32 f0 [2] 26 eb [2] 29 f1 [2] 37 ec [2] 35 ed [2] 2e eb [2] 32 ec [2] 2e c3 }

  condition:
    any of them
}