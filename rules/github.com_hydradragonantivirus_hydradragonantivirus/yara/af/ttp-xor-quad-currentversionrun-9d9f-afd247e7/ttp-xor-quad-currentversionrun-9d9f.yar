rule TTP_XOR_QUAD_CurrentVersionRun_9d9f {
  strings:
    $key_9d9f = { ce f0 [2] ea fe [2] c1 d2 [2] ef f0 [2] fb eb [2] f4 f1 [2] ea ec [2] e8 ed [2] f3 eb [2] ef ec [2] f3 c3 }

  condition:
    any of them
}