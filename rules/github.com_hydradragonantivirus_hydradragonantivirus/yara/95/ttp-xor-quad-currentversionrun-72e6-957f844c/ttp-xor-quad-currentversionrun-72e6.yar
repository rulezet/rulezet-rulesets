rule TTP_XOR_QUAD_CurrentVersionRun_72e6 {
  strings:
    $key_72e6 = { 21 89 [2] 05 87 [2] 2e ab [2] 00 89 [2] 14 92 [2] 1b 88 [2] 05 95 [2] 07 94 [2] 1c 92 [2] 00 95 [2] 1c ba }

  condition:
    any of them
}