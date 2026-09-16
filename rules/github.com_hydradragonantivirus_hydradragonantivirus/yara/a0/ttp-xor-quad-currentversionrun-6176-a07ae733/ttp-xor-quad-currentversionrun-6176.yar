rule TTP_XOR_QUAD_CurrentVersionRun_6176 {
  strings:
    $key_6176 = { 32 19 [2] 16 17 [2] 3d 3b [2] 13 19 [2] 07 02 [2] 08 18 [2] 16 05 [2] 14 04 [2] 0f 02 [2] 13 05 [2] 0f 2a }

  condition:
    any of them
}