rule TTP_XOR_QUAD_CurrentVersionRun_fac4 {
  strings:
    $key_fac4 = { a9 ab [2] 8d a5 [2] a6 89 [2] 88 ab [2] 9c b0 [2] 93 aa [2] 8d b7 [2] 8f b6 [2] 94 b0 [2] 88 b7 [2] 94 98 }

  condition:
    any of them
}