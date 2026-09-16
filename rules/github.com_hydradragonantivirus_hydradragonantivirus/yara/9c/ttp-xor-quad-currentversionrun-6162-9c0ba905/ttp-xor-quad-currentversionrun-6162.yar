rule TTP_XOR_QUAD_CurrentVersionRun_6162 {
  strings:
    $key_6162 = { 32 0d [2] 16 03 [2] 3d 2f [2] 13 0d [2] 07 16 [2] 08 0c [2] 16 11 [2] 14 10 [2] 0f 16 [2] 13 11 [2] 0f 3e }

  condition:
    any of them
}