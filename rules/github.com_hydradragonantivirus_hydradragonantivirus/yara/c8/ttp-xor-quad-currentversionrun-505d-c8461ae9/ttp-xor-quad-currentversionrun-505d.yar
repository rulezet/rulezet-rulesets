rule TTP_XOR_QUAD_CurrentVersionRun_505d {
  strings:
    $key_505d = { 03 32 [2] 27 3c [2] 0c 10 [2] 22 32 [2] 36 29 [2] 39 33 [2] 27 2e [2] 25 2f [2] 3e 29 [2] 22 2e [2] 3e 01 }

  condition:
    any of them
}