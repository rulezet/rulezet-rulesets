rule TTP_XOR_QUAD_CurrentVersionRun_5bc0 {
  strings:
    $key_5bc0 = { 08 af [2] 2c a1 [2] 07 8d [2] 29 af [2] 3d b4 [2] 32 ae [2] 2c b3 [2] 2e b2 [2] 35 b4 [2] 29 b3 [2] 35 9c }

  condition:
    any of them
}