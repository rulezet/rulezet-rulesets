rule TTP_XOR_QUAD_CurrentVersionRun_9084 {
  strings:
    $key_9084 = { c3 eb [2] e7 e5 [2] cc c9 [2] e2 eb [2] f6 f0 [2] f9 ea [2] e7 f7 [2] e5 f6 [2] fe f0 [2] e2 f7 [2] fe d8 }

  condition:
    any of them
}