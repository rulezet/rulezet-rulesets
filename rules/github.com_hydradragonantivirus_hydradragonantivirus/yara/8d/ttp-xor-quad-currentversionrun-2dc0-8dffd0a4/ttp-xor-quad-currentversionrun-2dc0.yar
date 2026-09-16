rule TTP_XOR_QUAD_CurrentVersionRun_2dc0 {
  strings:
    $key_2dc0 = { 7e af [2] 5a a1 [2] 71 8d [2] 5f af [2] 4b b4 [2] 44 ae [2] 5a b3 [2] 58 b2 [2] 43 b4 [2] 5f b3 [2] 43 9c }

  condition:
    any of them
}