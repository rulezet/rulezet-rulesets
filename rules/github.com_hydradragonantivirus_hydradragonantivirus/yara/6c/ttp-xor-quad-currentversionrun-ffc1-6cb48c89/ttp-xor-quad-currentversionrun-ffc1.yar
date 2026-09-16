rule TTP_XOR_QUAD_CurrentVersionRun_ffc1 {
  strings:
    $key_ffc1 = { ac ae [2] 88 a0 [2] a3 8c [2] 8d ae [2] 99 b5 [2] 96 af [2] 88 b2 [2] 8a b3 [2] 91 b5 [2] 8d b2 [2] 91 9d }

  condition:
    any of them
}