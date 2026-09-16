rule TTP_XOR_QUAD_CurrentVersionRun_285d {
  strings:
    $key_285d = { 7b 32 [2] 5f 3c [2] 74 10 [2] 5a 32 [2] 4e 29 [2] 41 33 [2] 5f 2e [2] 5d 2f [2] 46 29 [2] 5a 2e [2] 46 01 }

  condition:
    any of them
}