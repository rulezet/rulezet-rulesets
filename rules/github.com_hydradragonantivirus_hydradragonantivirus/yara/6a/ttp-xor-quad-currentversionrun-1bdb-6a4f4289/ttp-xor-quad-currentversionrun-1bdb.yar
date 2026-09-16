rule TTP_XOR_QUAD_CurrentVersionRun_1bdb {
  strings:
    $key_1bdb = { 48 b4 [2] 6c ba [2] 47 96 [2] 69 b4 [2] 7d af [2] 72 b5 [2] 6c a8 [2] 6e a9 [2] 75 af [2] 69 a8 [2] 75 87 }

  condition:
    any of them
}