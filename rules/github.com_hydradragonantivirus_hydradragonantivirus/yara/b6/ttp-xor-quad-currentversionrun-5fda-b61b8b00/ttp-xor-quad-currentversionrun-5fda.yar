rule TTP_XOR_QUAD_CurrentVersionRun_5fda {
  strings:
    $key_5fda = { 0c b5 [2] 28 bb [2] 03 97 [2] 2d b5 [2] 39 ae [2] 36 b4 [2] 28 a9 [2] 2a a8 [2] 31 ae [2] 2d a9 [2] 31 86 }

  condition:
    any of them
}