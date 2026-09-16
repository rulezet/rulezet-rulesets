rule TTP_XOR_QUAD_CurrentVersionRun_614e {
  strings:
    $key_614e = { 32 21 [2] 16 2f [2] 3d 03 [2] 13 21 [2] 07 3a [2] 08 20 [2] 16 3d [2] 14 3c [2] 0f 3a [2] 13 3d [2] 0f 12 }

  condition:
    any of them
}