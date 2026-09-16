rule TTP_XOR_QUAD_CurrentVersionRun_27e6 {
  strings:
    $key_27e6 = { 74 89 [2] 50 87 [2] 7b ab [2] 55 89 [2] 41 92 [2] 4e 88 [2] 50 95 [2] 52 94 [2] 49 92 [2] 55 95 [2] 49 ba }

  condition:
    any of them
}