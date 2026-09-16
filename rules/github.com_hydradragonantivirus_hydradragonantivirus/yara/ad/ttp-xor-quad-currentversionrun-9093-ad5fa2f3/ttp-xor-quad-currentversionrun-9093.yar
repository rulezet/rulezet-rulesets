rule TTP_XOR_QUAD_CurrentVersionRun_9093 {
  strings:
    $key_9093 = { c3 fc [2] e7 f2 [2] cc de [2] e2 fc [2] f6 e7 [2] f9 fd [2] e7 e0 [2] e5 e1 [2] fe e7 [2] e2 e0 [2] fe cf }

  condition:
    any of them
}