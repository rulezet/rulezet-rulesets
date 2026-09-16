rule TTP_XOR_QUAD_CurrentVersionRun_6e26 {
  strings:
    $key_6e26 = { 3d 49 [2] 19 47 [2] 32 6b [2] 1c 49 [2] 08 52 [2] 07 48 [2] 19 55 [2] 1b 54 [2] 00 52 [2] 1c 55 [2] 00 7a }

  condition:
    any of them
}