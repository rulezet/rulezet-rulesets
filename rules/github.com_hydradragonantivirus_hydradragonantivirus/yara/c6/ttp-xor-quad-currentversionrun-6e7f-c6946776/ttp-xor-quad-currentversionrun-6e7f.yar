rule TTP_XOR_QUAD_CurrentVersionRun_6e7f {
  strings:
    $key_6e7f = { 3d 10 [2] 19 1e [2] 32 32 [2] 1c 10 [2] 08 0b [2] 07 11 [2] 19 0c [2] 1b 0d [2] 00 0b [2] 1c 0c [2] 00 23 }

  condition:
    any of them
}