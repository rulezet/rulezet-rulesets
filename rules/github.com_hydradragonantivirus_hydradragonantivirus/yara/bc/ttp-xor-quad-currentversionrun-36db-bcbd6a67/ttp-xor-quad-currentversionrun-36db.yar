rule TTP_XOR_QUAD_CurrentVersionRun_36db {
  strings:
    $key_36db = { 65 b4 [2] 41 ba [2] 6a 96 [2] 44 b4 [2] 50 af [2] 5f b5 [2] 41 a8 [2] 43 a9 [2] 58 af [2] 44 a8 [2] 58 87 }

  condition:
    any of them
}