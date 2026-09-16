rule TTP_XOR_QUAD_CurrentVersionRun_6127 {
  strings:
    $key_6127 = { 32 48 [2] 16 46 [2] 3d 6a [2] 13 48 [2] 07 53 [2] 08 49 [2] 16 54 [2] 14 55 [2] 0f 53 [2] 13 54 [2] 0f 7b }

  condition:
    any of them
}