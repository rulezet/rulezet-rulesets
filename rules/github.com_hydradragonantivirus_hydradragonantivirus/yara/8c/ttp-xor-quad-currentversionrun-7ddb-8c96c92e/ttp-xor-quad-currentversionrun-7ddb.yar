rule TTP_XOR_QUAD_CurrentVersionRun_7ddb {
  strings:
    $key_7ddb = { 2e b4 [2] 0a ba [2] 21 96 [2] 0f b4 [2] 1b af [2] 14 b5 [2] 0a a8 [2] 08 a9 [2] 13 af [2] 0f a8 [2] 13 87 }

  condition:
    any of them
}