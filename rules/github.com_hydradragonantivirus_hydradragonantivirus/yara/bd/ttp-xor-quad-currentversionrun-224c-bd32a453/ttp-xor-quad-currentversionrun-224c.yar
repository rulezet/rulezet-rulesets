rule TTP_XOR_QUAD_CurrentVersionRun_224c {
  strings:
    $key_224c = { 71 23 [2] 55 2d [2] 7e 01 [2] 50 23 [2] 44 38 [2] 4b 22 [2] 55 3f [2] 57 3e [2] 4c 38 [2] 50 3f [2] 4c 10 }

  condition:
    any of them
}