rule TTP_XOR_QUAD_CurrentVersionRun_11e6 {
  strings:
    $key_11e6 = { 42 89 [2] 66 87 [2] 4d ab [2] 63 89 [2] 77 92 [2] 78 88 [2] 66 95 [2] 64 94 [2] 7f 92 [2] 63 95 [2] 7f ba }

  condition:
    any of them
}