rule TTP_XOR_QUAD_CurrentVersionRun_21e6 {
  strings:
    $key_21e6 = { 72 89 [2] 56 87 [2] 7d ab [2] 53 89 [2] 47 92 [2] 48 88 [2] 56 95 [2] 54 94 [2] 4f 92 [2] 53 95 [2] 4f ba }

  condition:
    any of them
}