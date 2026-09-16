rule TTP_XOR_QUAD_CurrentVersionRun_31e6 {
  strings:
    $key_31e6 = { 62 89 [2] 46 87 [2] 6d ab [2] 43 89 [2] 57 92 [2] 58 88 [2] 46 95 [2] 44 94 [2] 5f 92 [2] 43 95 [2] 5f ba }

  condition:
    any of them
}