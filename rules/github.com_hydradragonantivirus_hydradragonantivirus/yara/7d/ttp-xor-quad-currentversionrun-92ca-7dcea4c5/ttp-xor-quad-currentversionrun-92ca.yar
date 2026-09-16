rule TTP_XOR_QUAD_CurrentVersionRun_92ca {
  strings:
    $key_92ca = { c1 a5 [2] e5 ab [2] ce 87 [2] e0 a5 [2] f4 be [2] fb a4 [2] e5 b9 [2] e7 b8 [2] fc be [2] e0 b9 [2] fc 96 }

  condition:
    any of them
}