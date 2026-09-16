rule TTP_XOR_QUAD_CurrentVersionRun_24db {
  strings:
    $key_24db = { 77 b4 [2] 53 ba [2] 78 96 [2] 56 b4 [2] 42 af [2] 4d b5 [2] 53 a8 [2] 51 a9 [2] 4a af [2] 56 a8 [2] 4a 87 }

  condition:
    any of them
}