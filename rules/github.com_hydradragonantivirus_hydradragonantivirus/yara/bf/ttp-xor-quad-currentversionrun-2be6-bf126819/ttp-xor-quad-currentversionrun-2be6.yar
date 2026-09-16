rule TTP_XOR_QUAD_CurrentVersionRun_2be6 {
  strings:
    $key_2be6 = { 78 89 [2] 5c 87 [2] 77 ab [2] 59 89 [2] 4d 92 [2] 42 88 [2] 5c 95 [2] 5e 94 [2] 45 92 [2] 59 95 [2] 45 ba }

  condition:
    any of them
}