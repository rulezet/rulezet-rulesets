rule TTP_XOR_QUAD_CurrentVersionRun_5402 {
  strings:
    $key_5402 = { 07 6d [2] 23 63 [2] 08 4f [2] 26 6d [2] 32 76 [2] 3d 6c [2] 23 71 [2] 21 70 [2] 3a 76 [2] 26 71 [2] 3a 5e }

  condition:
    any of them
}