rule TTP_XOR_QUAD_CurrentVersionRun_7e5c {
  strings:
    $key_7e5c = { 2d 33 [2] 09 3d [2] 22 11 [2] 0c 33 [2] 18 28 [2] 17 32 [2] 09 2f [2] 0b 2e [2] 10 28 [2] 0c 2f [2] 10 00 }

  condition:
    any of them
}