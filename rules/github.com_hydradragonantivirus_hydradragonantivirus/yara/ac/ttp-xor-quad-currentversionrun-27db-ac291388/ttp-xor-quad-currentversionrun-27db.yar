rule TTP_XOR_QUAD_CurrentVersionRun_27db {
  strings:
    $key_27db = { 74 b4 [2] 50 ba [2] 7b 96 [2] 55 b4 [2] 41 af [2] 4e b5 [2] 50 a8 [2] 52 a9 [2] 49 af [2] 55 a8 [2] 49 87 }

  condition:
    any of them
}