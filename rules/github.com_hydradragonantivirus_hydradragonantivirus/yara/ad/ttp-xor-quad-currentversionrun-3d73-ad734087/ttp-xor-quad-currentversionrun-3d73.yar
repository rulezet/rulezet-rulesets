rule TTP_XOR_QUAD_CurrentVersionRun_3d73 {
  strings:
    $key_3d73 = { 6e 1c [2] 4a 12 [2] 61 3e [2] 4f 1c [2] 5b 07 [2] 54 1d [2] 4a 00 [2] 48 01 [2] 53 07 [2] 4f 00 [2] 53 2f }

  condition:
    any of them
}