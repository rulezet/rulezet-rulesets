rule TTP_XOR_QUAD_CurrentVersionRun_70c0 {
  strings:
    $key_70c0 = { 23 af [2] 07 a1 [2] 2c 8d [2] 02 af [2] 16 b4 [2] 19 ae [2] 07 b3 [2] 05 b2 [2] 1e b4 [2] 02 b3 [2] 1e 9c }

  condition:
    any of them
}