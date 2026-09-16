rule TTP_XOR_QUAD_CurrentVersionRun_7cc0 {
  strings:
    $key_7cc0 = { 2f af [2] 0b a1 [2] 20 8d [2] 0e af [2] 1a b4 [2] 15 ae [2] 0b b3 [2] 09 b2 [2] 12 b4 [2] 0e b3 [2] 12 9c }

  condition:
    any of them
}