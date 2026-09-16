rule TTP_XOR_QUAD_CurrentVersionRun_2ddb {
  strings:
    $key_2ddb = { 7e b4 [2] 5a ba [2] 71 96 [2] 5f b4 [2] 4b af [2] 44 b5 [2] 5a a8 [2] 58 a9 [2] 43 af [2] 5f a8 [2] 43 87 }

  condition:
    any of them
}