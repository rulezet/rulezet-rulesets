rule TTP_XOR_QUAD_CurrentVersionRun_6e3b {
  strings:
    $key_6e3b = { 3d 54 [2] 19 5a [2] 32 76 [2] 1c 54 [2] 08 4f [2] 07 55 [2] 19 48 [2] 1b 49 [2] 00 4f [2] 1c 48 [2] 00 67 }

  condition:
    any of them
}