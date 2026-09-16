rule TTP_XOR_QUAD_CurrentVersionRun_315c {
  strings:
    $key_315c = { 62 33 [2] 46 3d [2] 6d 11 [2] 43 33 [2] 57 28 [2] 58 32 [2] 46 2f [2] 44 2e [2] 5f 28 [2] 43 2f [2] 5f 00 }

  condition:
    any of them
}