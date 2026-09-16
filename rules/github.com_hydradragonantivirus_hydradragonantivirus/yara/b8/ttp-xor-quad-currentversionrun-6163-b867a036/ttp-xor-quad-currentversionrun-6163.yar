rule TTP_XOR_QUAD_CurrentVersionRun_6163 {
  strings:
    $key_6163 = { 32 0c [2] 16 02 [2] 3d 2e [2] 13 0c [2] 07 17 [2] 08 0d [2] 16 10 [2] 14 11 [2] 0f 17 [2] 13 10 [2] 0f 3f }

  condition:
    any of them
}