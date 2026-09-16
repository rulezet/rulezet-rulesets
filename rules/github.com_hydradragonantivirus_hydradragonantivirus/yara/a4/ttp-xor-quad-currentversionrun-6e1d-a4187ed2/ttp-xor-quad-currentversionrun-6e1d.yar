rule TTP_XOR_QUAD_CurrentVersionRun_6e1d {
  strings:
    $key_6e1d = { 3d 72 [2] 19 7c [2] 32 50 [2] 1c 72 [2] 08 69 [2] 07 73 [2] 19 6e [2] 1b 6f [2] 00 69 [2] 1c 6e [2] 00 41 }

  condition:
    any of them
}