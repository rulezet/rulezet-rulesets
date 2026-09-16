rule TTP_XOR_QUAD_CurrentVersionRun_e8c0 {
  strings:
    $key_e8c0 = { bb af [2] 9f a1 [2] b4 8d [2] 9a af [2] 8e b4 [2] 81 ae [2] 9f b3 [2] 9d b2 [2] 86 b4 [2] 9a b3 [2] 86 9c }

  condition:
    any of them
}