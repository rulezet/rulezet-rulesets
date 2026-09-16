rule TTP_XOR_QUAD_CurrentVersionRun_224d {
  strings:
    $key_224d = { 71 22 [2] 55 2c [2] 7e 00 [2] 50 22 [2] 44 39 [2] 4b 23 [2] 55 3e [2] 57 3f [2] 4c 39 [2] 50 3e [2] 4c 11 }

  condition:
    any of them
}