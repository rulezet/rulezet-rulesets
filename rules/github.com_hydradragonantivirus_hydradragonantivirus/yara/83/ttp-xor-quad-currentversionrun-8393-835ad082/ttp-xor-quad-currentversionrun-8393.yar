rule TTP_XOR_QUAD_CurrentVersionRun_8393 {
  strings:
    $key_8393 = { d0 fc [2] f4 f2 [2] df de [2] f1 fc [2] e5 e7 [2] ea fd [2] f4 e0 [2] f6 e1 [2] ed e7 [2] f1 e0 [2] ed cf }

  condition:
    any of them
}