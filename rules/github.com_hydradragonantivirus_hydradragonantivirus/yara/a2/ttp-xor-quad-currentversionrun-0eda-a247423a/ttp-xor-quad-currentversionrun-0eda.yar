rule TTP_XOR_QUAD_CurrentVersionRun_0eda {
  strings:
    $key_0eda = { 5d b5 [2] 79 bb [2] 52 97 [2] 7c b5 [2] 68 ae [2] 67 b4 [2] 79 a9 [2] 7b a8 [2] 60 ae [2] 7c a9 [2] 60 86 }

  condition:
    any of them
}