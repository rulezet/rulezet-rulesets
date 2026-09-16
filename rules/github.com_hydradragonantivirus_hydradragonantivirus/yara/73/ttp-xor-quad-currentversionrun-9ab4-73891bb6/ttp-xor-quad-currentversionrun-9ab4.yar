rule TTP_XOR_QUAD_CurrentVersionRun_9ab4 {
  strings:
    $key_9ab4 = { c9 db [2] ed d5 [2] c6 f9 [2] e8 db [2] fc c0 [2] f3 da [2] ed c7 [2] ef c6 [2] f4 c0 [2] e8 c7 [2] f4 e8 }

  condition:
    any of them
}