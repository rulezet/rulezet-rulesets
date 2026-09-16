rule TTP_XOR_QUAD_CurrentVersionRun_0c9f {
  strings:
    $key_0c9f = { 5f f0 [2] 7b fe [2] 50 d2 [2] 7e f0 [2] 6a eb [2] 65 f1 [2] 7b ec [2] 79 ed [2] 62 eb [2] 7e ec [2] 62 c3 }

  condition:
    any of them
}