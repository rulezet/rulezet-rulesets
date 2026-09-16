rule TTP_XOR_QUAD_CurrentVersionRun_7c9f {
  strings:
    $key_7c9f = { 2f f0 [2] 0b fe [2] 20 d2 [2] 0e f0 [2] 1a eb [2] 15 f1 [2] 0b ec [2] 09 ed [2] 12 eb [2] 0e ec [2] 12 c3 }

  condition:
    any of them
}