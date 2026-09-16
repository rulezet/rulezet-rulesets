rule TTP_XOR_QUAD_CurrentVersionRun_6fda {
  strings:
    $key_6fda = { 3c b5 [2] 18 bb [2] 33 97 [2] 1d b5 [2] 09 ae [2] 06 b4 [2] 18 a9 [2] 1a a8 [2] 01 ae [2] 1d a9 [2] 01 86 }

  condition:
    any of them
}