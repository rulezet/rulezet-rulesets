rule TTP_XOR_QUAD_CurrentVersionRun_26c0 {
  strings:
    $key_26c0 = { 75 af [2] 51 a1 [2] 7a 8d [2] 54 af [2] 40 b4 [2] 4f ae [2] 51 b3 [2] 53 b2 [2] 48 b4 [2] 54 b3 [2] 48 9c }

  condition:
    any of them
}