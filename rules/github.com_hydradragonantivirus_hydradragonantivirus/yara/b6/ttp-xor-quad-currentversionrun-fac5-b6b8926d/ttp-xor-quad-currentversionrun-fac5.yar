rule TTP_XOR_QUAD_CurrentVersionRun_fac5 {
  strings:
    $key_fac5 = { a9 aa [2] 8d a4 [2] a6 88 [2] 88 aa [2] 9c b1 [2] 93 ab [2] 8d b6 [2] 8f b7 [2] 94 b1 [2] 88 b6 [2] 94 99 }

  condition:
    any of them
}