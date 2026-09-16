rule TTP_XOR_QUAD_CurrentVersionRun_ffd4 {
  strings:
    $key_ffd4 = { ac bb [2] 88 b5 [2] a3 99 [2] 8d bb [2] 99 a0 [2] 96 ba [2] 88 a7 [2] 8a a6 [2] 91 a0 [2] 8d a7 [2] 91 88 }

  condition:
    any of them
}