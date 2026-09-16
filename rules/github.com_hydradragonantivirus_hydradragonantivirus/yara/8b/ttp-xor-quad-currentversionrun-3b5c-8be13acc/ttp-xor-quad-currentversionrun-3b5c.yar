rule TTP_XOR_QUAD_CurrentVersionRun_3b5c {
  strings:
    $key_3b5c = { 68 33 [2] 4c 3d [2] 67 11 [2] 49 33 [2] 5d 28 [2] 52 32 [2] 4c 2f [2] 4e 2e [2] 55 28 [2] 49 2f [2] 55 00 }

  condition:
    any of them
}