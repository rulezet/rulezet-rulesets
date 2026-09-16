rule TTP_XOR_QUAD_CurrentVersionRun_06c0 {
  strings:
    $key_06c0 = { 55 af [2] 71 a1 [2] 5a 8d [2] 74 af [2] 60 b4 [2] 6f ae [2] 71 b3 [2] 73 b2 [2] 68 b4 [2] 74 b3 [2] 68 9c }

  condition:
    any of them
}