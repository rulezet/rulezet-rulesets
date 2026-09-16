rule TTP_XOR_QUAD_CurrentVersionRun_e7c1 {
  strings:
    $key_e7c1 = { b4 ae [2] 90 a0 [2] bb 8c [2] 95 ae [2] 81 b5 [2] 8e af [2] 90 b2 [2] 92 b3 [2] 89 b5 [2] 95 b2 [2] 89 9d }

  condition:
    any of them
}