rule TTP_XOR_QUAD_CurrentVersionRun_6a4d {
  strings:
    $key_6a4d = { 39 22 [2] 1d 2c [2] 36 00 [2] 18 22 [2] 0c 39 [2] 03 23 [2] 1d 3e [2] 1f 3f [2] 04 39 [2] 18 3e [2] 04 11 }

  condition:
    any of them
}