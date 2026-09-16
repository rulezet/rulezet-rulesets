rule TTP_XOR_QUAD_CurrentVersionRun_6e0c {
  strings:
    $key_6e0c = { 3d 63 [2] 19 6d [2] 32 41 [2] 1c 63 [2] 08 78 [2] 07 62 [2] 19 7f [2] 1b 7e [2] 00 78 [2] 1c 7f [2] 00 50 }

  condition:
    any of them
}