rule TTP_XOR_QUAD_CurrentVersionRun_fcc0 {
  strings:
    $key_fcc0 = { af af [2] 8b a1 [2] a0 8d [2] 8e af [2] 9a b4 [2] 95 ae [2] 8b b3 [2] 89 b2 [2] 92 b4 [2] 8e b3 [2] 92 9c }

  condition:
    any of them
}