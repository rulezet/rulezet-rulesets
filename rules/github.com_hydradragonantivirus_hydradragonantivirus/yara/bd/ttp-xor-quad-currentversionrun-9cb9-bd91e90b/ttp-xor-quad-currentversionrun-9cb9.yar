rule TTP_XOR_QUAD_CurrentVersionRun_9cb9 {
  strings:
    $key_9cb9 = { cf d6 [2] eb d8 [2] c0 f4 [2] ee d6 [2] fa cd [2] f5 d7 [2] eb ca [2] e9 cb [2] f2 cd [2] ee ca [2] f2 e5 }

  condition:
    any of them
}