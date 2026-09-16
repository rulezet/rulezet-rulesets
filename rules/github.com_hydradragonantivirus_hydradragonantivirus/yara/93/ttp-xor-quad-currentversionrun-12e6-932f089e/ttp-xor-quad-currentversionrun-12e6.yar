rule TTP_XOR_QUAD_CurrentVersionRun_12e6 {
  strings:
    $key_12e6 = { 41 89 [2] 65 87 [2] 4e ab [2] 60 89 [2] 74 92 [2] 7b 88 [2] 65 95 [2] 67 94 [2] 7c 92 [2] 60 95 [2] 7c ba }

  condition:
    any of them
}