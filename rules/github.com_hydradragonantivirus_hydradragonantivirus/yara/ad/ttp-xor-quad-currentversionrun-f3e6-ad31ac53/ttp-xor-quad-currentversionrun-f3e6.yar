rule TTP_XOR_QUAD_CurrentVersionRun_f3e6 {
  strings:
    $key_f3e6 = { a0 89 [2] 84 87 [2] af ab [2] 81 89 [2] 95 92 [2] 9a 88 [2] 84 95 [2] 86 94 [2] 9d 92 [2] 81 95 [2] 9d ba }

  condition:
    any of them
}