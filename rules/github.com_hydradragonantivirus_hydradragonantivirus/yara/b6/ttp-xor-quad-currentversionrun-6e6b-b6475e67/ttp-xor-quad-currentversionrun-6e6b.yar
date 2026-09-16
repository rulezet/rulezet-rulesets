rule TTP_XOR_QUAD_CurrentVersionRun_6e6b {
  strings:
    $key_6e6b = { 3d 04 [2] 19 0a [2] 32 26 [2] 1c 04 [2] 08 1f [2] 07 05 [2] 19 18 [2] 1b 19 [2] 00 1f [2] 1c 18 [2] 00 37 }

  condition:
    any of them
}