rule TTP_XOR_QUAD_CurrentVersionRun_1d5c {
  strings:
    $key_1d5c = { 4e 33 [2] 6a 3d [2] 41 11 [2] 6f 33 [2] 7b 28 [2] 74 32 [2] 6a 2f [2] 68 2e [2] 73 28 [2] 6f 2f [2] 73 00 }

  condition:
    any of them
}