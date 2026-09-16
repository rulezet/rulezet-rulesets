rule TTP_XOR_QUAD_CurrentVersionRun_96ca {
  strings:
    $key_96ca = { c5 a5 [2] e1 ab [2] ca 87 [2] e4 a5 [2] f0 be [2] ff a4 [2] e1 b9 [2] e3 b8 [2] f8 be [2] e4 b9 [2] f8 96 }

  condition:
    any of them
}