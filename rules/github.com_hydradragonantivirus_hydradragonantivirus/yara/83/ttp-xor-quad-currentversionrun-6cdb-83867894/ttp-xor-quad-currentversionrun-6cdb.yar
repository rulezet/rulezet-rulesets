rule TTP_XOR_QUAD_CurrentVersionRun_6cdb {
  strings:
    $key_6cdb = { 3f b4 [2] 1b ba [2] 30 96 [2] 1e b4 [2] 0a af [2] 05 b5 [2] 1b a8 [2] 19 a9 [2] 02 af [2] 1e a8 [2] 02 87 }

  condition:
    any of them
}