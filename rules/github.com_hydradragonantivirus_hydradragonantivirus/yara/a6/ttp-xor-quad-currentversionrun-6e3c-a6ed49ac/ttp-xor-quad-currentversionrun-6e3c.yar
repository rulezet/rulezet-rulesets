rule TTP_XOR_QUAD_CurrentVersionRun_6e3c {
  strings:
    $key_6e3c = { 3d 53 [2] 19 5d [2] 32 71 [2] 1c 53 [2] 08 48 [2] 07 52 [2] 19 4f [2] 1b 4e [2] 00 48 [2] 1c 4f [2] 00 60 }

  condition:
    any of them
}