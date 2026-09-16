rule TTP_XOR_QUAD_CurrentVersionRun_3c9f {
  strings:
    $key_3c9f = { 6f f0 [2] 4b fe [2] 60 d2 [2] 4e f0 [2] 5a eb [2] 55 f1 [2] 4b ec [2] 49 ed [2] 52 eb [2] 4e ec [2] 52 c3 }

  condition:
    any of them
}