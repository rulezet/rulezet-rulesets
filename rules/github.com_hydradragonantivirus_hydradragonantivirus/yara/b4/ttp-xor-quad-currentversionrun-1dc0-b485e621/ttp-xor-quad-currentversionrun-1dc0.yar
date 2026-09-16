rule TTP_XOR_QUAD_CurrentVersionRun_1dc0 {
  strings:
    $key_1dc0 = { 4e af [2] 6a a1 [2] 41 8d [2] 6f af [2] 7b b4 [2] 74 ae [2] 6a b3 [2] 68 b2 [2] 73 b4 [2] 6f b3 [2] 73 9c }

  condition:
    any of them
}