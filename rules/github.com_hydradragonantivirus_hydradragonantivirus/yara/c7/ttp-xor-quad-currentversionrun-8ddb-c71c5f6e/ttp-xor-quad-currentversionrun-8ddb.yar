rule TTP_XOR_QUAD_CurrentVersionRun_8ddb {
  strings:
    $key_8ddb = { de b4 [2] fa ba [2] d1 96 [2] ff b4 [2] eb af [2] e4 b5 [2] fa a8 [2] f8 a9 [2] e3 af [2] ff a8 [2] e3 87 }

  condition:
    any of them
}