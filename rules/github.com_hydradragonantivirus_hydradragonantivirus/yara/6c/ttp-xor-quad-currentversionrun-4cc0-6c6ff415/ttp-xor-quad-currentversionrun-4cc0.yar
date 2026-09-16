rule TTP_XOR_QUAD_CurrentVersionRun_4cc0 {
  strings:
    $key_4cc0 = { 1f af [2] 3b a1 [2] 10 8d [2] 3e af [2] 2a b4 [2] 25 ae [2] 3b b3 [2] 39 b2 [2] 22 b4 [2] 3e b3 [2] 22 9c }

  condition:
    any of them
}