rule TTP_XOR_QUAD_CurrentVersionRun_6e64 {
  strings:
    $key_6e64 = { 3d 0b [2] 19 05 [2] 32 29 [2] 1c 0b [2] 08 10 [2] 07 0a [2] 19 17 [2] 1b 16 [2] 00 10 [2] 1c 17 [2] 00 38 }

  condition:
    any of them
}