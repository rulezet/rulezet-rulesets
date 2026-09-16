rule TTP_XOR_QUAD_CurrentVersionRun_1b5c {
  strings:
    $key_1b5c = { 48 33 [2] 6c 3d [2] 47 11 [2] 69 33 [2] 7d 28 [2] 72 32 [2] 6c 2f [2] 6e 2e [2] 75 28 [2] 69 2f [2] 75 00 }

  condition:
    any of them
}