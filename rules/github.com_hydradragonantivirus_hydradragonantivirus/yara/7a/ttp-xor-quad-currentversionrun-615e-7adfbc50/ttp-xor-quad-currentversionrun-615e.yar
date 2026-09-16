rule TTP_XOR_QUAD_CurrentVersionRun_615e {
  strings:
    $key_615e = { 32 31 [2] 16 3f [2] 3d 13 [2] 13 31 [2] 07 2a [2] 08 30 [2] 16 2d [2] 14 2c [2] 0f 2a [2] 13 2d [2] 0f 02 }

  condition:
    any of them
}