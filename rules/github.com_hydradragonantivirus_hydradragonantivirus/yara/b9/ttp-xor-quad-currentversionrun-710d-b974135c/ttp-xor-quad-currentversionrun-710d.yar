rule TTP_XOR_QUAD_CurrentVersionRun_710d {
  strings:
    $key_710d = { 22 62 [2] 06 6c [2] 2d 40 [2] 03 62 [2] 17 79 [2] 18 63 [2] 06 7e [2] 04 7f [2] 1f 79 [2] 03 7e [2] 1f 51 }

  condition:
    any of them
}