rule TTP_XOR_QUAD_CurrentVersionRun_3a4d {
  strings:
    $key_3a4d = { 69 22 [2] 4d 2c [2] 66 00 [2] 48 22 [2] 5c 39 [2] 53 23 [2] 4d 3e [2] 4f 3f [2] 54 39 [2] 48 3e [2] 54 11 }

  condition:
    any of them
}