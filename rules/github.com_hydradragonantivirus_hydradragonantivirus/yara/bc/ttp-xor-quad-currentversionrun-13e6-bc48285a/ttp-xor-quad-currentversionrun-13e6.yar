rule TTP_XOR_QUAD_CurrentVersionRun_13e6 {
  strings:
    $key_13e6 = { 40 89 [2] 64 87 [2] 4f ab [2] 61 89 [2] 75 92 [2] 7a 88 [2] 64 95 [2] 66 94 [2] 7d 92 [2] 61 95 [2] 7d ba }

  condition:
    any of them
}