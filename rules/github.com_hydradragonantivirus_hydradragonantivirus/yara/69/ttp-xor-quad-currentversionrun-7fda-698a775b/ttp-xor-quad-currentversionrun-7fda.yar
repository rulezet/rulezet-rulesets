rule TTP_XOR_QUAD_CurrentVersionRun_7fda {
  strings:
    $key_7fda = { 2c b5 [2] 08 bb [2] 23 97 [2] 0d b5 [2] 19 ae [2] 16 b4 [2] 08 a9 [2] 0a a8 [2] 11 ae [2] 0d a9 [2] 11 86 }

  condition:
    any of them
}