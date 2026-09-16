rule TTP_XOR_QUAD_CurrentVersionRun_f6c1 {
  strings:
    $key_f6c1 = { a5 ae [2] 81 a0 [2] aa 8c [2] 84 ae [2] 90 b5 [2] 9f af [2] 81 b2 [2] 83 b3 [2] 98 b5 [2] 84 b2 [2] 98 9d }

  condition:
    any of them
}