rule TTP_XOR_QUAD_CurrentVersionRun_3cc0 {
  strings:
    $key_3cc0 = { 6f af [2] 4b a1 [2] 60 8d [2] 4e af [2] 5a b4 [2] 55 ae [2] 4b b3 [2] 49 b2 [2] 52 b4 [2] 4e b3 [2] 52 9c }

  condition:
    any of them
}