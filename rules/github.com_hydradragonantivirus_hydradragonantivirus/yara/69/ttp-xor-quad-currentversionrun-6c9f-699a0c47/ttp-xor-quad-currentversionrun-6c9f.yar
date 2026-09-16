rule TTP_XOR_QUAD_CurrentVersionRun_6c9f {
  strings:
    $key_6c9f = { 3f f0 [2] 1b fe [2] 30 d2 [2] 1e f0 [2] 0a eb [2] 05 f1 [2] 1b ec [2] 19 ed [2] 02 eb [2] 1e ec [2] 02 c3 }

  condition:
    any of them
}