rule TTP_XOR_QUAD_CurrentVersionRun_36c1 {
  strings:
    $key_36c1 = { 65 ae [2] 41 a0 [2] 6a 8c [2] 44 ae [2] 50 b5 [2] 5f af [2] 41 b2 [2] 43 b3 [2] 58 b5 [2] 44 b2 [2] 58 9d }

  condition:
    any of them
}