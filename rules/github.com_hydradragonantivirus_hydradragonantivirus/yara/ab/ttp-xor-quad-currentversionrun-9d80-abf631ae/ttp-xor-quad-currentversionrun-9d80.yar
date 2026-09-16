rule TTP_XOR_QUAD_CurrentVersionRun_9d80 {
  strings:
    $key_9d80 = { ce ef [2] ea e1 [2] c1 cd [2] ef ef [2] fb f4 [2] f4 ee [2] ea f3 [2] e8 f2 [2] f3 f4 [2] ef f3 [2] f3 dc }

  condition:
    any of them
}