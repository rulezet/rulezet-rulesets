rule TTP_XOR_QUAD_CurrentVersionRun_47c1 {
  strings:
    $key_47c1 = { 14 ae [2] 30 a0 [2] 1b 8c [2] 35 ae [2] 21 b5 [2] 2e af [2] 30 b2 [2] 32 b3 [2] 29 b5 [2] 35 b2 [2] 29 9d }

  condition:
    any of them
}