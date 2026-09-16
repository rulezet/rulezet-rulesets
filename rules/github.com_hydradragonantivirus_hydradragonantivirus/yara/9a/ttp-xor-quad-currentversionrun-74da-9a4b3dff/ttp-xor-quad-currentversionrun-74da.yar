rule TTP_XOR_QUAD_CurrentVersionRun_74da {
  strings:
    $key_74da = { 27 b5 [2] 03 bb [2] 28 97 [2] 06 b5 [2] 12 ae [2] 1d b4 [2] 03 a9 [2] 01 a8 [2] 1a ae [2] 06 a9 [2] 1a 86 }

  condition:
    any of them
}