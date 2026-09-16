rule TTP_XOR_QUAD_CurrentVersionRun_616f {
  strings:
    $key_616f = { 32 00 [2] 16 0e [2] 3d 22 [2] 13 00 [2] 07 1b [2] 08 01 [2] 16 1c [2] 14 1d [2] 0f 1b [2] 13 1c [2] 0f 33 }

  condition:
    any of them
}