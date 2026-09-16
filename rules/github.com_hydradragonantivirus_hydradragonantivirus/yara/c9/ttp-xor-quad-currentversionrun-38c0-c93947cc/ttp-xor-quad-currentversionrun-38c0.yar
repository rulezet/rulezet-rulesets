rule TTP_XOR_QUAD_CurrentVersionRun_38c0 {
  strings:
    $key_38c0 = { 6b af [2] 4f a1 [2] 64 8d [2] 4a af [2] 5e b4 [2] 51 ae [2] 4f b3 [2] 4d b2 [2] 56 b4 [2] 4a b3 [2] 56 9c }

  condition:
    any of them
}