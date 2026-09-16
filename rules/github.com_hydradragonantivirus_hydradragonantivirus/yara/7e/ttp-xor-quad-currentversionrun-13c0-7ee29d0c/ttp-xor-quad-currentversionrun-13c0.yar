rule TTP_XOR_QUAD_CurrentVersionRun_13c0 {
  strings:
    $key_13c0 = { 40 af [2] 64 a1 [2] 4f 8d [2] 61 af [2] 75 b4 [2] 7a ae [2] 64 b3 [2] 66 b2 [2] 7d b4 [2] 61 b3 [2] 7d 9c }

  condition:
    any of them
}