rule TTP_XOR_QUAD_CurrentVersionRun_4b5d {
  strings:
    $key_4b5d = { 18 32 [2] 3c 3c [2] 17 10 [2] 39 32 [2] 2d 29 [2] 22 33 [2] 3c 2e [2] 3e 2f [2] 25 29 [2] 39 2e [2] 25 01 }

  condition:
    any of them
}