rule TTP_XOR_QUAD_CurrentVersionRun_ffd7 {
  strings:
    $key_ffd7 = { ac b8 [2] 88 b6 [2] a3 9a [2] 8d b8 [2] 99 a3 [2] 96 b9 [2] 88 a4 [2] 8a a5 [2] 91 a3 [2] 8d a4 [2] 91 8b }

  condition:
    any of them
}