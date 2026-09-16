rule TTP_XOR_QUAD_CurrentVersionRun_6eed {
  strings:
    $key_6eed = { 3d 82 [2] 19 8c [2] 32 a0 [2] 1c 82 [2] 08 99 [2] 07 83 [2] 19 9e [2] 1b 9f [2] 00 99 [2] 1c 9e [2] 00 b1 }

  condition:
    any of them
}