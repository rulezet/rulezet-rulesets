rule TTP_XOR_QUAD_CurrentVersionRun_045d {
  strings:
    $key_045d = { 57 32 [2] 73 3c [2] 58 10 [2] 76 32 [2] 62 29 [2] 6d 33 [2] 73 2e [2] 71 2f [2] 6a 29 [2] 76 2e [2] 6a 01 }

  condition:
    any of them
}