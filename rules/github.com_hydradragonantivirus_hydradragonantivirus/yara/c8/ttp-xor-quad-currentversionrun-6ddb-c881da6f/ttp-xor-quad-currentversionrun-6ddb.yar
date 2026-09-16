rule TTP_XOR_QUAD_CurrentVersionRun_6ddb {
  strings:
    $key_6ddb = { 3e b4 [2] 1a ba [2] 31 96 [2] 1f b4 [2] 0b af [2] 04 b5 [2] 1a a8 [2] 18 a9 [2] 03 af [2] 1f a8 [2] 03 87 }

  condition:
    any of them
}