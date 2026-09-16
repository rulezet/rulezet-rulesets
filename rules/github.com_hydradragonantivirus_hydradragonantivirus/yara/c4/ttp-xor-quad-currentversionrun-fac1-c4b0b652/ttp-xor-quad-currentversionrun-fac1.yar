rule TTP_XOR_QUAD_CurrentVersionRun_fac1 {
  strings:
    $key_fac1 = { a9 ae [2] 8d a0 [2] a6 8c [2] 88 ae [2] 9c b5 [2] 93 af [2] 8d b2 [2] 8f b3 [2] 94 b5 [2] 88 b2 [2] 94 9d }

  condition:
    any of them
}