rule TTP_XOR_QUAD_CurrentVersionRun_6e09 {
  strings:
    $key_6e09 = { 3d 66 [2] 19 68 [2] 32 44 [2] 1c 66 [2] 08 7d [2] 07 67 [2] 19 7a [2] 1b 7b [2] 00 7d [2] 1c 7a [2] 00 55 }

  condition:
    any of them
}