rule TTP_XOR_QUAD_CurrentVersionRun_16e6 {
  strings:
    $key_16e6 = { 45 89 [2] 61 87 [2] 4a ab [2] 64 89 [2] 70 92 [2] 7f 88 [2] 61 95 [2] 63 94 [2] 78 92 [2] 64 95 [2] 78 ba }

  condition:
    any of them
}