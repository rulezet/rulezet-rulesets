rule TTP_XOR_QUAD_CurrentVersionRun_6e33 {
  strings:
    $key_6e33 = { 3d 5c [2] 19 52 [2] 32 7e [2] 1c 5c [2] 08 47 [2] 07 5d [2] 19 40 [2] 1b 41 [2] 00 47 [2] 1c 40 [2] 00 6f }

  condition:
    any of them
}