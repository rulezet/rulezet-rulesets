rule TTP_XOR_QUAD_CurrentVersionRun_6be6 {
  strings:
    $key_6be6 = { 38 89 [2] 1c 87 [2] 37 ab [2] 19 89 [2] 0d 92 [2] 02 88 [2] 1c 95 [2] 1e 94 [2] 05 92 [2] 19 95 [2] 05 ba }

  condition:
    any of them
}