rule TTP_XOR_QUAD_CurrentVersionRun_6e3f {
  strings:
    $key_6e3f = { 3d 50 [2] 19 5e [2] 32 72 [2] 1c 50 [2] 08 4b [2] 07 51 [2] 19 4c [2] 1b 4d [2] 00 4b [2] 1c 4c [2] 00 63 }

  condition:
    any of them
}