rule TTP_XOR_QUAD_CurrentVersionRun_6e6d {
  strings:
    $key_6e6d = { 3d 02 [2] 19 0c [2] 32 20 [2] 1c 02 [2] 08 19 [2] 07 03 [2] 19 1e [2] 1b 1f [2] 00 19 [2] 1c 1e [2] 00 31 }

  condition:
    any of them
}