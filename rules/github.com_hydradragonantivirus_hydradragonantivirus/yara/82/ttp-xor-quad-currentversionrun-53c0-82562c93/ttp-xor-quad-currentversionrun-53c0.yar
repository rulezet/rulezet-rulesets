rule TTP_XOR_QUAD_CurrentVersionRun_53c0 {
  strings:
    $key_53c0 = { 00 af [2] 24 a1 [2] 0f 8d [2] 21 af [2] 35 b4 [2] 3a ae [2] 24 b3 [2] 26 b2 [2] 3d b4 [2] 21 b3 [2] 3d 9c }

  condition:
    any of them
}