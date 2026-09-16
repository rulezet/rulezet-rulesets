rule TTP_XOR_QUAD_CurrentVersionRun_33c0 {
  strings:
    $key_33c0 = { 60 af [2] 44 a1 [2] 6f 8d [2] 41 af [2] 55 b4 [2] 5a ae [2] 44 b3 [2] 46 b2 [2] 5d b4 [2] 41 b3 [2] 5d 9c }

  condition:
    any of them
}