rule TTP_XOR_QUAD_CurrentVersionRun_e0e6 {
  strings:
    $key_e0e6 = { b3 89 [2] 97 87 [2] bc ab [2] 92 89 [2] 86 92 [2] 89 88 [2] 97 95 [2] 95 94 [2] 8e 92 [2] 92 95 [2] 8e ba }

  condition:
    any of them
}