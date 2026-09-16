rule TTP_XOR_QUAD_CurrentVersionRun_1f5d {
  strings:
    $key_1f5d = { 4c 32 [2] 68 3c [2] 43 10 [2] 6d 32 [2] 79 29 [2] 76 33 [2] 68 2e [2] 6a 2f [2] 71 29 [2] 6d 2e [2] 71 01 }

  condition:
    any of them
}