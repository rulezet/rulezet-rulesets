rule TTP_XOR_QUAD_CurrentVersionRun_73c0 {
  strings:
    $key_73c0 = { 20 af [2] 04 a1 [2] 2f 8d [2] 01 af [2] 15 b4 [2] 1a ae [2] 04 b3 [2] 06 b2 [2] 1d b4 [2] 01 b3 [2] 1d 9c }

  condition:
    any of them
}