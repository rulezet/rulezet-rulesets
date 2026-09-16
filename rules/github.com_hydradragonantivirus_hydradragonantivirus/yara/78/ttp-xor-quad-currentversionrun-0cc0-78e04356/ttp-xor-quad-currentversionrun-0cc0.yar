rule TTP_XOR_QUAD_CurrentVersionRun_0cc0 {
  strings:
    $key_0cc0 = { 5f af [2] 7b a1 [2] 50 8d [2] 7e af [2] 6a b4 [2] 65 ae [2] 7b b3 [2] 79 b2 [2] 62 b4 [2] 7e b3 [2] 62 9c }

  condition:
    any of them
}