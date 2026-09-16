rule TTP_XOR_QUAD_CurrentVersionRun_3f73 {
  strings:
    $key_3f73 = { 6c 1c [2] 48 12 [2] 63 3e [2] 4d 1c [2] 59 07 [2] 56 1d [2] 48 00 [2] 4a 01 [2] 51 07 [2] 4d 00 [2] 51 2f }

  condition:
    any of them
}