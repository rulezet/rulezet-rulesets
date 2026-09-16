rule TTP_XOR_QUAD_CurrentVersionRun_40d1 {
  strings:
    $key_40d1 = { 13 be [2] 37 b0 [2] 1c 9c [2] 32 be [2] 26 a5 [2] 29 bf [2] 37 a2 [2] 35 a3 [2] 2e a5 [2] 32 a2 [2] 2e 8d }

  condition:
    any of them
}