rule TTP_XOR_QUAD_CurrentVersionRun_9d96 {
  strings:
    $key_9d96 = { ce f9 [2] ea f7 [2] c1 db [2] ef f9 [2] fb e2 [2] f4 f8 [2] ea e5 [2] e8 e4 [2] f3 e2 [2] ef e5 [2] f3 ca }

  condition:
    any of them
}