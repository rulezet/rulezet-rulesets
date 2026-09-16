rule TTP_XOR_QUAD_CurrentVersionRun_57c0 {
  strings:
    $key_57c0 = { 04 af [2] 20 a1 [2] 0b 8d [2] 25 af [2] 31 b4 [2] 3e ae [2] 20 b3 [2] 22 b2 [2] 39 b4 [2] 25 b3 [2] 39 9c }

  condition:
    any of them
}