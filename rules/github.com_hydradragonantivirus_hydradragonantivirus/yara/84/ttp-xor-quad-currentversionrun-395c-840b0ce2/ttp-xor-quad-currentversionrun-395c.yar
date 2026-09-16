rule TTP_XOR_QUAD_CurrentVersionRun_395c {
  strings:
    $key_395c = { 6a 33 [2] 4e 3d [2] 65 11 [2] 4b 33 [2] 5f 28 [2] 50 32 [2] 4e 2f [2] 4c 2e [2] 57 28 [2] 4b 2f [2] 57 00 }

  condition:
    any of them
}