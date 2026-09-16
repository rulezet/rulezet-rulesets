rule TTP_XOR_QUAD_CurrentVersionRun_6113 {
  strings:
    $key_6113 = { 32 7c [2] 16 72 [2] 3d 5e [2] 13 7c [2] 07 67 [2] 08 7d [2] 16 60 [2] 14 61 [2] 0f 67 [2] 13 60 [2] 0f 4f }

  condition:
    any of them
}