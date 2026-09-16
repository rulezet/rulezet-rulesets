rule TTP_XOR_QUAD_CurrentVersionRun_6d5c {
  strings:
    $key_6d5c = { 3e 33 [2] 1a 3d [2] 31 11 [2] 1f 33 [2] 0b 28 [2] 04 32 [2] 1a 2f [2] 18 2e [2] 03 28 [2] 1f 2f [2] 03 00 }

  condition:
    any of them
}