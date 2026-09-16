rule TTP_XOR_QUAD_CurrentVersionRun_6e27 {
  strings:
    $key_6e27 = { 3d 48 [2] 19 46 [2] 32 6a [2] 1c 48 [2] 08 53 [2] 07 49 [2] 19 54 [2] 1b 55 [2] 00 53 [2] 1c 54 [2] 00 7b }

  condition:
    any of them
}