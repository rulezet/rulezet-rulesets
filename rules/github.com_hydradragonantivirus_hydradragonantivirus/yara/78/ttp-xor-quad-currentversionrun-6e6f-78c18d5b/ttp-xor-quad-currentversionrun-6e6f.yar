rule TTP_XOR_QUAD_CurrentVersionRun_6e6f {
  strings:
    $key_6e6f = { 3d 00 [2] 19 0e [2] 32 22 [2] 1c 00 [2] 08 1b [2] 07 01 [2] 19 1c [2] 1b 1d [2] 00 1b [2] 1c 1c [2] 00 33 }

  condition:
    any of them
}