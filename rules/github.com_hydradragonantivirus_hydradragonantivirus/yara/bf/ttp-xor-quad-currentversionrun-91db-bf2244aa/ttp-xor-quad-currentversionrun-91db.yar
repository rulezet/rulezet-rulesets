rule TTP_XOR_QUAD_CurrentVersionRun_91db {
  strings:
    $key_91db = { c2 b4 [2] e6 ba [2] cd 96 [2] e3 b4 [2] f7 af [2] f8 b5 [2] e6 a8 [2] e4 a9 [2] ff af [2] e3 a8 [2] ff 87 }

  condition:
    any of them
}