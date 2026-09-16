rule TTP_XOR_QUAD_CurrentVersionRun_e8c1 {
  strings:
    $key_e8c1 = { bb ae [2] 9f a0 [2] b4 8c [2] 9a ae [2] 8e b5 [2] 81 af [2] 9f b2 [2] 9d b3 [2] 86 b5 [2] 9a b2 [2] 86 9d }

  condition:
    any of them
}