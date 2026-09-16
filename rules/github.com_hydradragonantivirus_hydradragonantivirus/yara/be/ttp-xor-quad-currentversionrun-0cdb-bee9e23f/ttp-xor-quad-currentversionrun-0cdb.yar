rule TTP_XOR_QUAD_CurrentVersionRun_0cdb {
  strings:
    $key_0cdb = { 5f b4 [2] 7b ba [2] 50 96 [2] 7e b4 [2] 6a af [2] 65 b5 [2] 7b a8 [2] 79 a9 [2] 62 af [2] 7e a8 [2] 62 87 }

  condition:
    any of them
}