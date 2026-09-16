rule TTP_XOR_QUAD_CurrentVersionRun_6e36 {
  strings:
    $key_6e36 = { 3d 59 [2] 19 57 [2] 32 7b [2] 1c 59 [2] 08 42 [2] 07 58 [2] 19 45 [2] 1b 44 [2] 00 42 [2] 1c 45 [2] 00 6a }

  condition:
    any of them
}