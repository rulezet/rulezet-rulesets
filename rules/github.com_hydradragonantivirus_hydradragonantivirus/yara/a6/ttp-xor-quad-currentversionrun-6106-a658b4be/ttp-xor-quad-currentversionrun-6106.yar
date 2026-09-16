rule TTP_XOR_QUAD_CurrentVersionRun_6106 {
  strings:
    $key_6106 = { 32 69 [2] 16 67 [2] 3d 4b [2] 13 69 [2] 07 72 [2] 08 68 [2] 16 75 [2] 14 74 [2] 0f 72 [2] 13 75 [2] 0f 5a }

  condition:
    any of them
}