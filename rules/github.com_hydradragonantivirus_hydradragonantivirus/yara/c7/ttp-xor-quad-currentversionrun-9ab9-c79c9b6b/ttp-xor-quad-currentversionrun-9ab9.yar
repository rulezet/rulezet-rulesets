rule TTP_XOR_QUAD_CurrentVersionRun_9ab9 {
  strings:
    $key_9ab9 = { c9 d6 [2] ed d8 [2] c6 f4 [2] e8 d6 [2] fc cd [2] f3 d7 [2] ed ca [2] ef cb [2] f4 cd [2] e8 ca [2] f4 e5 }

  condition:
    any of them
}