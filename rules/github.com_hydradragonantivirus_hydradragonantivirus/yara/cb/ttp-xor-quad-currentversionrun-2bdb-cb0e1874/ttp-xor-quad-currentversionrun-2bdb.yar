rule TTP_XOR_QUAD_CurrentVersionRun_2bdb {
  strings:
    $key_2bdb = { 78 b4 [2] 5c ba [2] 77 96 [2] 59 b4 [2] 4d af [2] 42 b5 [2] 5c a8 [2] 5e a9 [2] 45 af [2] 59 a8 [2] 45 87 }

  condition:
    any of them
}