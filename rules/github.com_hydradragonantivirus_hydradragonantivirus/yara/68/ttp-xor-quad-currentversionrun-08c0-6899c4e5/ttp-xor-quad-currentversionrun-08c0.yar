rule TTP_XOR_QUAD_CurrentVersionRun_08c0 {
  strings:
    $key_08c0 = { 5b af [2] 7f a1 [2] 54 8d [2] 7a af [2] 6e b4 [2] 61 ae [2] 7f b3 [2] 7d b2 [2] 66 b4 [2] 7a b3 [2] 66 9c }

  condition:
    any of them
}