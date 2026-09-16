rule TTP_XOR_QUAD_CurrentVersionRun_ffdb {
  strings:
    $key_ffdb = { ac b4 [2] 88 ba [2] a3 96 [2] 8d b4 [2] 99 af [2] 96 b5 [2] 88 a8 [2] 8a a9 [2] 91 af [2] 8d a8 [2] 91 87 }

  condition:
    any of them
}