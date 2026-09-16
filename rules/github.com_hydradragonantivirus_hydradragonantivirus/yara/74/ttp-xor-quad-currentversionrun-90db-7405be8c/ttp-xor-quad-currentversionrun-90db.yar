rule TTP_XOR_QUAD_CurrentVersionRun_90db {
  strings:
    $key_90db = { c3 b4 [2] e7 ba [2] cc 96 [2] e2 b4 [2] f6 af [2] f9 b5 [2] e7 a8 [2] e5 a9 [2] fe af [2] e2 a8 [2] fe 87 }

  condition:
    any of them
}