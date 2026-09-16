rule TTP_XOR_QUAD_CurrentVersionRun_f6c0 {
  strings:
    $key_f6c0 = { a5 af [2] 81 a1 [2] aa 8d [2] 84 af [2] 90 b4 [2] 9f ae [2] 81 b3 [2] 83 b2 [2] 98 b4 [2] 84 b3 [2] 98 9c }

  condition:
    any of them
}