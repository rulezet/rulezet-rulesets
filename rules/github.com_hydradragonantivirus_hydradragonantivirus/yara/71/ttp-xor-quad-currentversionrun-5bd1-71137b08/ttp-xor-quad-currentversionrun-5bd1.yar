rule TTP_XOR_QUAD_CurrentVersionRun_5bd1 {
  strings:
    $key_5bd1 = { 08 be [2] 2c b0 [2] 07 9c [2] 29 be [2] 3d a5 [2] 32 bf [2] 2c a2 [2] 2e a3 [2] 35 a5 [2] 29 a2 [2] 35 8d }

  condition:
    any of them
}