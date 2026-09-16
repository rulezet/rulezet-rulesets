rule TTP_XOR_QUAD_CurrentVersionRun_6101 {
  strings:
    $key_6101 = { 32 6e [2] 16 60 [2] 3d 4c [2] 13 6e [2] 07 75 [2] 08 6f [2] 16 72 [2] 14 73 [2] 0f 75 [2] 13 72 [2] 0f 5d }

  condition:
    any of them
}