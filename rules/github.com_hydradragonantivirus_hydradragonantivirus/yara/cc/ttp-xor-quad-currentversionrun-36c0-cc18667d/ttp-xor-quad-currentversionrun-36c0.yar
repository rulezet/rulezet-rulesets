rule TTP_XOR_QUAD_CurrentVersionRun_36c0 {
  strings:
    $key_36c0 = { 65 af [2] 41 a1 [2] 6a 8d [2] 44 af [2] 50 b4 [2] 5f ae [2] 41 b3 [2] 43 b2 [2] 58 b4 [2] 44 b3 [2] 58 9c }

  condition:
    any of them
}