rule TTP_XOR_QUAD_CurrentVersionRun_0bdb {
  strings:
    $key_0bdb = { 58 b4 [2] 7c ba [2] 57 96 [2] 79 b4 [2] 6d af [2] 62 b5 [2] 7c a8 [2] 7e a9 [2] 65 af [2] 79 a8 [2] 65 87 }

  condition:
    any of them
}