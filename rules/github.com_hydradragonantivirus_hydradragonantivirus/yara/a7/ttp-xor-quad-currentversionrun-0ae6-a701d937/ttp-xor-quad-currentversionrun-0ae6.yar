rule TTP_XOR_QUAD_CurrentVersionRun_0ae6 {
  strings:
    $key_0ae6 = { 59 89 [2] 7d 87 [2] 56 ab [2] 78 89 [2] 6c 92 [2] 63 88 [2] 7d 95 [2] 7f 94 [2] 64 92 [2] 78 95 [2] 64 ba }

  condition:
    any of them
}