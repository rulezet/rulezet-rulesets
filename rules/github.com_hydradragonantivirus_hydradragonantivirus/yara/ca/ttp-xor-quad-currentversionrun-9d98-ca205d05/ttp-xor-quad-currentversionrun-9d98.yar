rule TTP_XOR_QUAD_CurrentVersionRun_9d98 {
  strings:
    $key_9d98 = { ce f7 [2] ea f9 [2] c1 d5 [2] ef f7 [2] fb ec [2] f4 f6 [2] ea eb [2] e8 ea [2] f3 ec [2] ef eb [2] f3 c4 }

  condition:
    any of them
}