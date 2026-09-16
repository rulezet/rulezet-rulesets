rule TTP_XOR_QUAD_CurrentVersionRun_06e6 {
  strings:
    $key_06e6 = { 55 89 [2] 71 87 [2] 5a ab [2] 74 89 [2] 60 92 [2] 6f 88 [2] 71 95 [2] 73 94 [2] 68 92 [2] 74 95 [2] 68 ba }

  condition:
    any of them
}