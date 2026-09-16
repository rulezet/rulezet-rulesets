rule TTP_XOR_QUAD_CurrentVersionRun_9aa5 {
  strings:
    $key_9aa5 = { c9 ca [2] ed c4 [2] c6 e8 [2] e8 ca [2] fc d1 [2] f3 cb [2] ed d6 [2] ef d7 [2] f4 d1 [2] e8 d6 [2] f4 f9 }

  condition:
    any of them
}