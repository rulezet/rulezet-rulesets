rule TTP_XOR_QUAD_CurrentVersionRun_9abc {
  strings:
    $key_9abc = { c9 d3 [2] ed dd [2] c6 f1 [2] e8 d3 [2] fc c8 [2] f3 d2 [2] ed cf [2] ef ce [2] f4 c8 [2] e8 cf [2] f4 e0 }

  condition:
    any of them
}