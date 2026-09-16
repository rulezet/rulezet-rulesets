rule TTP_XOR_QUAD_CurrentVersionRun_9a80 {
  strings:
    $key_9a80 = { c9 ef [2] ed e1 [2] c6 cd [2] e8 ef [2] fc f4 [2] f3 ee [2] ed f3 [2] ef f2 [2] f4 f4 [2] e8 f3 [2] f4 dc }

  condition:
    any of them
}