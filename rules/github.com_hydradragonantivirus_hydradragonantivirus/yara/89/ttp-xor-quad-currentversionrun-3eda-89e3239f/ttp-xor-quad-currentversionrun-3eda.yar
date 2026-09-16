rule TTP_XOR_QUAD_CurrentVersionRun_3eda {
  strings:
    $key_3eda = { 6d b5 [2] 49 bb [2] 62 97 [2] 4c b5 [2] 58 ae [2] 57 b4 [2] 49 a9 [2] 4b a8 [2] 50 ae [2] 4c a9 [2] 50 86 }

  condition:
    any of them
}