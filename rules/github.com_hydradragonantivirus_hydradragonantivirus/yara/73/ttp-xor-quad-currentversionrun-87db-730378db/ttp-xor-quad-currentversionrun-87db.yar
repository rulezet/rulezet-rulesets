rule TTP_XOR_QUAD_CurrentVersionRun_87db {
  strings:
    $key_87db = { d4 b4 [2] f0 ba [2] db 96 [2] f5 b4 [2] e1 af [2] ee b5 [2] f0 a8 [2] f2 a9 [2] e9 af [2] f5 a8 [2] e9 87 }

  condition:
    any of them
}