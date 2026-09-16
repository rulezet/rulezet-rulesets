rule TTP_XOR_QUAD_CurrentVersionRun_5bc1 {
  strings:
    $key_5bc1 = { 08 ae [2] 2c a0 [2] 07 8c [2] 29 ae [2] 3d b5 [2] 32 af [2] 2c b2 [2] 2e b3 [2] 35 b5 [2] 29 b2 [2] 35 9d }

  condition:
    any of them
}