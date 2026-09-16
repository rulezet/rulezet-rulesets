rule TTP_XOR_QUAD_CurrentVersionRun_9096 {
  strings:
    $key_9096 = { c3 f9 [2] e7 f7 [2] cc db [2] e2 f9 [2] f6 e2 [2] f9 f8 [2] e7 e5 [2] e5 e4 [2] fe e2 [2] e2 e5 [2] fe ca }

  condition:
    any of them
}