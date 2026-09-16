rule TTP_XOR_QUAD_CurrentVersionRun_6e00 {
  strings:
    $key_6e00 = { 3d 6f [2] 19 61 [2] 32 4d [2] 1c 6f [2] 08 74 [2] 07 6e [2] 19 73 [2] 1b 72 [2] 00 74 [2] 1c 73 [2] 00 5c }

  condition:
    any of them
}