rule TTP_XOR_QUAD_CurrentVersionRun_1a53 {
  strings:
    $key_1a53 = { 49 3c [2] 6d 32 [2] 46 1e [2] 68 3c [2] 7c 27 [2] 73 3d [2] 6d 20 [2] 6f 21 [2] 74 27 [2] 68 20 [2] 74 0f }

  condition:
    any of them
}