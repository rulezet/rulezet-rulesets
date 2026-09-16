rule TTP_XOR_QUAD_CurrentVersionRun_1cdb {
  strings:
    $key_1cdb = { 4f b4 [2] 6b ba [2] 40 96 [2] 6e b4 [2] 7a af [2] 75 b5 [2] 6b a8 [2] 69 a9 [2] 72 af [2] 6e a8 [2] 72 87 }

  condition:
    any of them
}