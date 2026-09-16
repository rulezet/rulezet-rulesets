rule TTP_XOR_QUAD_CurrentVersionRun_155c {
  strings:
    $key_155c = { 46 33 [2] 62 3d [2] 49 11 [2] 67 33 [2] 73 28 [2] 7c 32 [2] 62 2f [2] 60 2e [2] 7b 28 [2] 67 2f [2] 7b 00 }

  condition:
    any of them
}