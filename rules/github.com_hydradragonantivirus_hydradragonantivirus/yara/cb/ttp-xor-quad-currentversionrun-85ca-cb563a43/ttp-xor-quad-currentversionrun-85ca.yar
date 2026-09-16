rule TTP_XOR_QUAD_CurrentVersionRun_85ca {
  strings:
    $key_85ca = { d6 a5 [2] f2 ab [2] d9 87 [2] f7 a5 [2] e3 be [2] ec a4 [2] f2 b9 [2] f0 b8 [2] eb be [2] f7 b9 [2] eb 96 }

  condition:
    any of them
}