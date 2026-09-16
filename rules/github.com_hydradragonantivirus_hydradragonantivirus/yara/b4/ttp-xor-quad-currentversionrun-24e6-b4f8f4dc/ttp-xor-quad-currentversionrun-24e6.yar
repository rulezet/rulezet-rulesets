rule TTP_XOR_QUAD_CurrentVersionRun_24e6 {
  strings:
    $key_24e6 = { 77 89 [2] 53 87 [2] 78 ab [2] 56 89 [2] 42 92 [2] 4d 88 [2] 53 95 [2] 51 94 [2] 4a 92 [2] 56 95 [2] 4a ba }

  condition:
    any of them
}