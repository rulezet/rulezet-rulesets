rule TTP_XOR_QUAD_CurrentVersionRun_3f4d {
  strings:
    $key_3f4d = { 6c 22 [2] 48 2c [2] 63 00 [2] 4d 22 [2] 59 39 [2] 56 23 [2] 48 3e [2] 4a 3f [2] 51 39 [2] 4d 3e [2] 51 11 }

  condition:
    any of them
}