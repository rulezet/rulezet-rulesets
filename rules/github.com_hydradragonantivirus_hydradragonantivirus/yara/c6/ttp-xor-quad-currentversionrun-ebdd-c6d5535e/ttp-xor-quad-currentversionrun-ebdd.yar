rule TTP_XOR_QUAD_CurrentVersionRun_ebdd {
  strings:
    $key_ebdd = { b8 b2 [2] 9c bc [2] b7 90 [2] 99 b2 [2] 8d a9 [2] 82 b3 [2] 9c ae [2] 9e af [2] 85 a9 [2] 99 ae [2] 85 81 }

  condition:
    any of them
}