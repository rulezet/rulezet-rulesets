rule TTP_XOR_QUAD_CurrentVersionRun_6107 {
  strings:
    $key_6107 = { 32 68 [2] 16 66 [2] 3d 4a [2] 13 68 [2] 07 73 [2] 08 69 [2] 16 74 [2] 14 75 [2] 0f 73 [2] 13 74 [2] 0f 5b }

  condition:
    any of them
}