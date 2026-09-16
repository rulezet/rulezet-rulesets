rule TTP_XOR_QUAD_CurrentVersionRun_2add {
  strings:
    $key_2add = { 79 b2 [2] 5d bc [2] 76 90 [2] 58 b2 [2] 4c a9 [2] 43 b3 [2] 5d ae [2] 5f af [2] 44 a9 [2] 58 ae [2] 44 81 }

  condition:
    any of them
}