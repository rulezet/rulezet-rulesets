rule TTP_XOR_QUAD_CurrentVersionRun_9696 {
  strings:
    $key_9696 = { c5 f9 [2] e1 f7 [2] ca db [2] e4 f9 [2] f0 e2 [2] ff f8 [2] e1 e5 [2] e3 e4 [2] f8 e2 [2] e4 e5 [2] f8 ca }

  condition:
    any of them
}