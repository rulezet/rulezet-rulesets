rule TTP_XOR_QUAD_CurrentVersionRun_05db {
  strings:
    $key_05db = { 56 b4 [2] 72 ba [2] 59 96 [2] 77 b4 [2] 63 af [2] 6c b5 [2] 72 a8 [2] 70 a9 [2] 6b af [2] 77 a8 [2] 6b 87 }

  condition:
    any of them
}