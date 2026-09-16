rule TTP_XOR_QUAD_CurrentVersionRun_6e02 {
  strings:
    $key_6e02 = { 3d 6d [2] 19 63 [2] 32 4f [2] 1c 6d [2] 08 76 [2] 07 6c [2] 19 71 [2] 1b 70 [2] 00 76 [2] 1c 71 [2] 00 5e }

  condition:
    any of them
}