rule TTP_XOR_QUAD_CurrentVersionRun_23e6 {
  strings:
    $key_23e6 = { 70 89 [2] 54 87 [2] 7f ab [2] 51 89 [2] 45 92 [2] 4a 88 [2] 54 95 [2] 56 94 [2] 4d 92 [2] 51 95 [2] 4d ba }

  condition:
    any of them
}