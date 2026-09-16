rule TTP_XOR_QUAD_CurrentVersionRun_8293 {
  strings:
    $key_8293 = { d1 fc [2] f5 f2 [2] de de [2] f0 fc [2] e4 e7 [2] eb fd [2] f5 e0 [2] f7 e1 [2] ec e7 [2] f0 e0 [2] ec cf }

  condition:
    any of them
}