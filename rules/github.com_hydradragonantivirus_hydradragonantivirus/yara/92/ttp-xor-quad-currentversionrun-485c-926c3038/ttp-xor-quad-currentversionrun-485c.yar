rule TTP_XOR_QUAD_CurrentVersionRun_485c {
  strings:
    $key_485c = { 1b 33 [2] 3f 3d [2] 14 11 [2] 3a 33 [2] 2e 28 [2] 21 32 [2] 3f 2f [2] 3d 2e [2] 26 28 [2] 3a 2f [2] 26 00 }

  condition:
    any of them
}