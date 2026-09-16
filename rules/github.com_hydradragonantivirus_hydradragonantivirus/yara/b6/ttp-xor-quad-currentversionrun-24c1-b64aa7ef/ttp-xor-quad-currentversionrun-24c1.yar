rule TTP_XOR_QUAD_CurrentVersionRun_24c1 {
  strings:
    $key_24c1 = { 77 ae [2] 53 a0 [2] 78 8c [2] 56 ae [2] 42 b5 [2] 4d af [2] 53 b2 [2] 51 b3 [2] 4a b5 [2] 56 b2 [2] 4a 9d }

  condition:
    any of them
}