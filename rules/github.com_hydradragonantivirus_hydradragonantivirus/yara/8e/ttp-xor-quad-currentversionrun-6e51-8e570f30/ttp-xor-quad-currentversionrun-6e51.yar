rule TTP_XOR_QUAD_CurrentVersionRun_6e51 {
  strings:
    $key_6e51 = { 3d 3e [2] 19 30 [2] 32 1c [2] 1c 3e [2] 08 25 [2] 07 3f [2] 19 22 [2] 1b 23 [2] 00 25 [2] 1c 22 [2] 00 0d }

  condition:
    any of them
}