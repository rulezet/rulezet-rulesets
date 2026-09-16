rule TTP_XOR_QUAD_CurrentVersionRun_fac6 {
  strings:
    $key_fac6 = { a9 a9 [2] 8d a7 [2] a6 8b [2] 88 a9 [2] 9c b2 [2] 93 a8 [2] 8d b5 [2] 8f b4 [2] 94 b2 [2] 88 b5 [2] 94 9a }

  condition:
    any of them
}