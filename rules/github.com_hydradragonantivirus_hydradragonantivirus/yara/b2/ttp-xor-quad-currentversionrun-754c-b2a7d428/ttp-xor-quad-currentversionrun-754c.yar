rule TTP_XOR_QUAD_CurrentVersionRun_754c {
  strings:
    $key_754c = { 26 23 [2] 02 2d [2] 29 01 [2] 07 23 [2] 13 38 [2] 1c 22 [2] 02 3f [2] 00 3e [2] 1b 38 [2] 07 3f [2] 1b 10 }

  condition:
    any of them
}