rule TTP_XOR_QUAD_CurrentVersionRun_01c0 {
  strings:
    $key_01c0 = { 52 af [2] 76 a1 [2] 5d 8d [2] 73 af [2] 67 b4 [2] 68 ae [2] 76 b3 [2] 74 b2 [2] 6f b4 [2] 73 b3 [2] 6f 9c }

  condition:
    any of them
}