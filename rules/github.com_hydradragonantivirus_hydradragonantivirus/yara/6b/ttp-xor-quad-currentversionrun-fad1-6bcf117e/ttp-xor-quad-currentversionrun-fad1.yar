rule TTP_XOR_QUAD_CurrentVersionRun_fad1 {
  strings:
    $key_fad1 = { a9 be [2] 8d b0 [2] a6 9c [2] 88 be [2] 9c a5 [2] 93 bf [2] 8d a2 [2] 8f a3 [2] 94 a5 [2] 88 a2 [2] 94 8d }

  condition:
    any of them
}