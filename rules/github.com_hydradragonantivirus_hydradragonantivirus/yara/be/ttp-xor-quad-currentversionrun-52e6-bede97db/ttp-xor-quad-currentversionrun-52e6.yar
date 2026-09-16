rule TTP_XOR_QUAD_CurrentVersionRun_52e6 {
  strings:
    $key_52e6 = { 01 89 [2] 25 87 [2] 0e ab [2] 20 89 [2] 34 92 [2] 3b 88 [2] 25 95 [2] 27 94 [2] 3c 92 [2] 20 95 [2] 3c ba }

  condition:
    any of them
}