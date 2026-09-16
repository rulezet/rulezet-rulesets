rule TTP_XOR_QUAD_CurrentVersionRun_6e52 {
  strings:
    $key_6e52 = { 3d 3d [2] 19 33 [2] 32 1f [2] 1c 3d [2] 08 26 [2] 07 3c [2] 19 21 [2] 1b 20 [2] 00 26 [2] 1c 21 [2] 00 0e }

  condition:
    any of them
}