rule TTP_XOR_QUAD_CurrentVersionRun_285c {
  strings:
    $key_285c = { 7b 33 [2] 5f 3d [2] 74 11 [2] 5a 33 [2] 4e 28 [2] 41 32 [2] 5f 2f [2] 5d 2e [2] 46 28 [2] 5a 2f [2] 46 00 }

  condition:
    any of them
}