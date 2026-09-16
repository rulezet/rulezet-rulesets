rule TTP_XOR_QUAD_CurrentVersionRun_0ddb {
  strings:
    $key_0ddb = { 5e b4 [2] 7a ba [2] 51 96 [2] 7f b4 [2] 6b af [2] 64 b5 [2] 7a a8 [2] 78 a9 [2] 63 af [2] 7f a8 [2] 63 87 }

  condition:
    any of them
}