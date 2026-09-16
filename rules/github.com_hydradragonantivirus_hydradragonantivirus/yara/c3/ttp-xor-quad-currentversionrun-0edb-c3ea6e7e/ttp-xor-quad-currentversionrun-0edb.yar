rule TTP_XOR_QUAD_CurrentVersionRun_0edb {
  strings:
    $key_0edb = { 5d b4 [2] 79 ba [2] 52 96 [2] 7c b4 [2] 68 af [2] 67 b5 [2] 79 a8 [2] 7b a9 [2] 60 af [2] 7c a8 [2] 60 87 }

  condition:
    any of them
}