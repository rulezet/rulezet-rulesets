rule TTP_XOR_QUAD_CurrentVersionRun_53db {
  strings:
    $key_53db = { 00 b4 [2] 24 ba [2] 0f 96 [2] 21 b4 [2] 35 af [2] 3a b5 [2] 24 a8 [2] 26 a9 [2] 3d af [2] 21 a8 [2] 3d 87 }

  condition:
    any of them
}