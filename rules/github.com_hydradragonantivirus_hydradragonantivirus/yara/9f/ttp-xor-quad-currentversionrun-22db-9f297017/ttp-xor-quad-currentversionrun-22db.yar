rule TTP_XOR_QUAD_CurrentVersionRun_22db {
  strings:
    $key_22db = { 71 b4 [2] 55 ba [2] 7e 96 [2] 50 b4 [2] 44 af [2] 4b b5 [2] 55 a8 [2] 57 a9 [2] 4c af [2] 50 a8 [2] 4c 87 }

  condition:
    any of them
}