rule TTP_XOR_QUAD_CurrentVersionRun_9aae {
  strings:
    $key_9aae = { c9 c1 [2] ed cf [2] c6 e3 [2] e8 c1 [2] fc da [2] f3 c0 [2] ed dd [2] ef dc [2] f4 da [2] e8 dd [2] f4 f2 }

  condition:
    any of them
}