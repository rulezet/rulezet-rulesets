rule TTP_XOR_QUAD_CurrentVersionRun_ffc7 {
  strings:
    $key_ffc7 = { ac a8 [2] 88 a6 [2] a3 8a [2] 8d a8 [2] 99 b3 [2] 96 a9 [2] 88 b4 [2] 8a b5 [2] 91 b3 [2] 8d b4 [2] 91 9b }

  condition:
    any of them
}