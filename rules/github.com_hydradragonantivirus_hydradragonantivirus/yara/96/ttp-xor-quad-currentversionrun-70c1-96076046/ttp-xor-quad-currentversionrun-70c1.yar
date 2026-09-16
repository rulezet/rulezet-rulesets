rule TTP_XOR_QUAD_CurrentVersionRun_70c1 {
  strings:
    $key_70c1 = { 23 ae [2] 07 a0 [2] 2c 8c [2] 02 ae [2] 16 b5 [2] 19 af [2] 07 b2 [2] 05 b3 [2] 1e b5 [2] 02 b2 [2] 1e 9d }

  condition:
    any of them
}