rule TTP_XOR_QUAD_CurrentVersionRun_5bdb {
  strings:
    $key_5bdb = { 08 b4 [2] 2c ba [2] 07 96 [2] 29 b4 [2] 3d af [2] 32 b5 [2] 2c a8 [2] 2e a9 [2] 35 af [2] 29 a8 [2] 35 87 }

  condition:
    any of them
}