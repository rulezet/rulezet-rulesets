rule TTP_XOR_QUAD_CurrentVersionRun_5cdb {
  strings:
    $key_5cdb = { 0f b4 [2] 2b ba [2] 00 96 [2] 2e b4 [2] 3a af [2] 35 b5 [2] 2b a8 [2] 29 a9 [2] 32 af [2] 2e a8 [2] 32 87 }

  condition:
    any of them
}