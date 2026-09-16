rule TTP_XOR_QUAD_CurrentVersionRun_61ed {
  strings:
    $key_61ed = { 32 82 [2] 16 8c [2] 3d a0 [2] 13 82 [2] 07 99 [2] 08 83 [2] 16 9e [2] 14 9f [2] 0f 99 [2] 13 9e [2] 0f b1 }

  condition:
    any of them
}