rule TTP_XOR_QUAD_CurrentVersionRun_9a96 {
  strings:
    $key_9a96 = { c9 f9 [2] ed f7 [2] c6 db [2] e8 f9 [2] fc e2 [2] f3 f8 [2] ed e5 [2] ef e4 [2] f4 e2 [2] e8 e5 [2] f4 ca }

  condition:
    any of them
}