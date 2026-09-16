rule TTP_XOR_QUAD_CurrentVersionRun_6e3e {
  strings:
    $key_6e3e = { 3d 51 [2] 19 5f [2] 32 73 [2] 1c 51 [2] 08 4a [2] 07 50 [2] 19 4d [2] 1b 4c [2] 00 4a [2] 1c 4d [2] 00 62 }

  condition:
    any of them
}