rule TTP_XOR_QUAD_CurrentVersionRun_40c1 {
  strings:
    $key_40c1 = { 13 ae [2] 37 a0 [2] 1c 8c [2] 32 ae [2] 26 b5 [2] 29 af [2] 37 b2 [2] 35 b3 [2] 2e b5 [2] 32 b2 [2] 2e 9d }

  condition:
    any of them
}