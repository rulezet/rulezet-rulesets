rule TTP_XOR_QUAD_CurrentVersionRun_23c0 {
  strings:
    $key_23c0 = { 70 af [2] 54 a1 [2] 7f 8d [2] 51 af [2] 45 b4 [2] 4a ae [2] 54 b3 [2] 56 b2 [2] 4d b4 [2] 51 b3 [2] 4d 9c }

  condition:
    any of them
}