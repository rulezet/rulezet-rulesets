rule TTP_XOR_QUAD_CurrentVersionRun_ffca {
  strings:
    $key_ffca = { ac a5 [2] 88 ab [2] a3 87 [2] 8d a5 [2] 99 be [2] 96 a4 [2] 88 b9 [2] 8a b8 [2] 91 be [2] 8d b9 [2] 91 96 }

  condition:
    any of them
}