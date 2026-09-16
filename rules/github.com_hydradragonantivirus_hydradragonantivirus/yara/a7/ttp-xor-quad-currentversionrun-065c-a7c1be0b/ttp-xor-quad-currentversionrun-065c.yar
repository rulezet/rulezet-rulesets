rule TTP_XOR_QUAD_CurrentVersionRun_065c {
  strings:
    $key_065c = { 55 33 [2] 71 3d [2] 5a 11 [2] 74 33 [2] 60 28 [2] 6f 32 [2] 71 2f [2] 73 2e [2] 68 28 [2] 74 2f [2] 68 00 }

  condition:
    any of them
}