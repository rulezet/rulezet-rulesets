rule TTP_XOR_QUAD_CurrentVersionRun_51e6 {
  strings:
    $key_51e6 = { 02 89 [2] 26 87 [2] 0d ab [2] 23 89 [2] 37 92 [2] 38 88 [2] 26 95 [2] 24 94 [2] 3f 92 [2] 23 95 [2] 3f ba }

  condition:
    any of them
}