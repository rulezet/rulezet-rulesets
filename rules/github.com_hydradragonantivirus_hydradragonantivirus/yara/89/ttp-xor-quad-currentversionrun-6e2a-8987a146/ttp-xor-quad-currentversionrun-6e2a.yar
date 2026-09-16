rule TTP_XOR_QUAD_CurrentVersionRun_6e2a {
  strings:
    $key_6e2a = { 3d 45 [2] 19 4b [2] 32 67 [2] 1c 45 [2] 08 5e [2] 07 44 [2] 19 59 [2] 1b 58 [2] 00 5e [2] 1c 59 [2] 00 76 }

  condition:
    any of them
}