rule TTP_XOR_QUAD_CurrentVersionRun_6103 {
  strings:
    $key_6103 = { 32 6c [2] 16 62 [2] 3d 4e [2] 13 6c [2] 07 77 [2] 08 6d [2] 16 70 [2] 14 71 [2] 0f 77 [2] 13 70 [2] 0f 5f }

  condition:
    any of them
}