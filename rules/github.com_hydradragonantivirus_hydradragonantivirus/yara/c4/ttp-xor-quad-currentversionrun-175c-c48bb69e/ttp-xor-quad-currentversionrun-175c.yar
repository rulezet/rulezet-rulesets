rule TTP_XOR_QUAD_CurrentVersionRun_175c {
  strings:
    $key_175c = { 44 33 [2] 60 3d [2] 4b 11 [2] 65 33 [2] 71 28 [2] 7e 32 [2] 60 2f [2] 62 2e [2] 79 28 [2] 65 2f [2] 79 00 }

  condition:
    any of them
}