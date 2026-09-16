rule TTP_XOR_QUAD_CurrentVersionRun_95ca {
  strings:
    $key_95ca = { c6 a5 [2] e2 ab [2] c9 87 [2] e7 a5 [2] f3 be [2] fc a4 [2] e2 b9 [2] e0 b8 [2] fb be [2] e7 b9 [2] fb 96 }

  condition:
    any of them
}