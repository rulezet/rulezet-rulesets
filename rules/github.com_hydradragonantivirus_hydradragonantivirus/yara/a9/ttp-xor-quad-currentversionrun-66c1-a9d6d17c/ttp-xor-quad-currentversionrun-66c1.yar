rule TTP_XOR_QUAD_CurrentVersionRun_66c1 {
  strings:
    $key_66c1 = { 35 ae [2] 11 a0 [2] 3a 8c [2] 14 ae [2] 00 b5 [2] 0f af [2] 11 b2 [2] 13 b3 [2] 08 b5 [2] 14 b2 [2] 08 9d }

  condition:
    any of them
}