rule TTP_XOR_QUAD_CurrentVersionRun_469f {
  strings:
    $key_469f = { 15 f0 [2] 31 fe [2] 1a d2 [2] 34 f0 [2] 20 eb [2] 2f f1 [2] 31 ec [2] 33 ed [2] 28 eb [2] 34 ec [2] 28 c3 }

  condition:
    any of them
}