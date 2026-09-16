rule TTP_XOR_QUAD_CurrentVersionRun_25c1 {
  strings:
    $key_25c1 = { 76 ae [2] 52 a0 [2] 79 8c [2] 57 ae [2] 43 b5 [2] 4c af [2] 52 b2 [2] 50 b3 [2] 4b b5 [2] 57 b2 [2] 4b 9d }

  condition:
    any of them
}