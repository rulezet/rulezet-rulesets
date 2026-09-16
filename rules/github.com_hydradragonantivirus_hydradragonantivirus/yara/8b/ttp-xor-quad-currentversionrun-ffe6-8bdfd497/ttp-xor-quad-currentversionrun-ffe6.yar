rule TTP_XOR_QUAD_CurrentVersionRun_ffe6 {
  strings:
    $key_ffe6 = { ac 89 [2] 88 87 [2] a3 ab [2] 8d 89 [2] 99 92 [2] 96 88 [2] 88 95 [2] 8a 94 [2] 91 92 [2] 8d 95 [2] 91 ba }

  condition:
    any of them
}