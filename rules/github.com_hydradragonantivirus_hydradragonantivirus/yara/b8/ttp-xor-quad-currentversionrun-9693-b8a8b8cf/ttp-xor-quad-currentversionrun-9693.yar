rule TTP_XOR_QUAD_CurrentVersionRun_9693 {
  strings:
    $key_9693 = { c5 fc [2] e1 f2 [2] ca de [2] e4 fc [2] f0 e7 [2] ff fd [2] e1 e0 [2] e3 e1 [2] f8 e7 [2] e4 e0 [2] f8 cf }

  condition:
    any of them
}