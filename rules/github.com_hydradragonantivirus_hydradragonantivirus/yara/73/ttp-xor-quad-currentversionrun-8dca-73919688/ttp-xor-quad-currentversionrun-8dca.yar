rule TTP_XOR_QUAD_CurrentVersionRun_8dca {
  strings:
    $key_8dca = { de a5 [2] fa ab [2] d1 87 [2] ff a5 [2] eb be [2] e4 a4 [2] fa b9 [2] f8 b8 [2] e3 be [2] ff b9 [2] e3 96 }

  condition:
    any of them
}