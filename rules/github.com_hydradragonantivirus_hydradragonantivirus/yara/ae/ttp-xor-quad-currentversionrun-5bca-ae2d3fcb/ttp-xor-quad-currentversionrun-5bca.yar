rule TTP_XOR_QUAD_CurrentVersionRun_5bca {
  strings:
    $key_5bca = { 08 a5 [2] 2c ab [2] 07 87 [2] 29 a5 [2] 3d be [2] 32 a4 [2] 2c b9 [2] 2e b8 [2] 35 be [2] 29 b9 [2] 35 96 }

  condition:
    any of them
}