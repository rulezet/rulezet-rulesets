rule TTP_XOR_QUAD_CurrentVersionRun_525d {
  strings:
    $key_525d = { 01 32 [2] 25 3c [2] 0e 10 [2] 20 32 [2] 34 29 [2] 3b 33 [2] 25 2e [2] 27 2f [2] 3c 29 [2] 20 2e [2] 3c 01 }

  condition:
    any of them
}