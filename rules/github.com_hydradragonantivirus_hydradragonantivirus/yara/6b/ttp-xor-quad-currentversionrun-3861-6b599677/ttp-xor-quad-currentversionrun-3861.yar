rule TTP_XOR_QUAD_CurrentVersionRun_3861 {
  strings:
    $key_3861 = { 6b 0e [2] 4f 00 [2] 64 2c [2] 4a 0e [2] 5e 15 [2] 51 0f [2] 4f 12 [2] 4d 13 [2] 56 15 [2] 4a 12 [2] 56 3d }

  condition:
    any of them
}