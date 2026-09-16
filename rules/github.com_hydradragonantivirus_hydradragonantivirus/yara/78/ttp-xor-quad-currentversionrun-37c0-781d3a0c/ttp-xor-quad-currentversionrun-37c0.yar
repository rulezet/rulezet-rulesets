rule TTP_XOR_QUAD_CurrentVersionRun_37c0 {
  strings:
    $key_37c0 = { 64 af [2] 40 a1 [2] 6b 8d [2] 45 af [2] 51 b4 [2] 5e ae [2] 40 b3 [2] 42 b2 [2] 59 b4 [2] 45 b3 [2] 59 9c }

  condition:
    any of them
}