rule TTP_XOR_QUAD_CurrentVersionRun_fad0 {
  strings:
    $key_fad0 = { a9 bf [2] 8d b1 [2] a6 9d [2] 88 bf [2] 9c a4 [2] 93 be [2] 8d a3 [2] 8f a2 [2] 94 a4 [2] 88 a3 [2] 94 8c }

  condition:
    any of them
}