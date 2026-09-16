rule TTP_XOR_QUAD_CurrentVersionRun_6e04 {
  strings:
    $key_6e04 = { 3d 6b [2] 19 65 [2] 32 49 [2] 1c 6b [2] 08 70 [2] 07 6a [2] 19 77 [2] 1b 76 [2] 00 70 [2] 1c 77 [2] 00 58 }

  condition:
    any of them
}