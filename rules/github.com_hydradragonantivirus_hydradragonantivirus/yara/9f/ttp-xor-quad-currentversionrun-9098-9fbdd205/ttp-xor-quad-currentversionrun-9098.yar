rule TTP_XOR_QUAD_CurrentVersionRun_9098 {
  strings:
    $key_9098 = { c3 f7 [2] e7 f9 [2] cc d5 [2] e2 f7 [2] f6 ec [2] f9 f6 [2] e7 eb [2] e5 ea [2] fe ec [2] e2 eb [2] fe c4 }

  condition:
    any of them
}