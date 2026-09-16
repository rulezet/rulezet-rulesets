rule TTP_XOR_QUAD_CurrentVersionRun_32db {
  strings:
    $key_32db = { 61 b4 [2] 45 ba [2] 6e 96 [2] 40 b4 [2] 54 af [2] 5b b5 [2] 45 a8 [2] 47 a9 [2] 5c af [2] 40 a8 [2] 5c 87 }

  condition:
    any of them
}