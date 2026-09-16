rule TTP_XOR_QUAD_CurrentVersionRun_02db {
  strings:
    $key_02db = { 51 b4 [2] 75 ba [2] 5e 96 [2] 70 b4 [2] 64 af [2] 6b b5 [2] 75 a8 [2] 77 a9 [2] 6c af [2] 70 a8 [2] 6c 87 }

  condition:
    any of them
}