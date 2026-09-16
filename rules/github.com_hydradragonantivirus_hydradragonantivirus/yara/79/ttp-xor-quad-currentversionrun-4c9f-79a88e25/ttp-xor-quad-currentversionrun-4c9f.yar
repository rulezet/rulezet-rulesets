rule TTP_XOR_QUAD_CurrentVersionRun_4c9f {
  strings:
    $key_4c9f = { 1f f0 [2] 3b fe [2] 10 d2 [2] 3e f0 [2] 2a eb [2] 25 f1 [2] 3b ec [2] 39 ed [2] 22 eb [2] 3e ec [2] 22 c3 }

  condition:
    any of them
}