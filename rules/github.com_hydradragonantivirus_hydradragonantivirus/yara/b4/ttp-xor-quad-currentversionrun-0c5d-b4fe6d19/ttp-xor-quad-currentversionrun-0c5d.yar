rule TTP_XOR_QUAD_CurrentVersionRun_0c5d {
  strings:
    $key_0c5d = { 5f 32 [2] 7b 3c [2] 50 10 [2] 7e 32 [2] 6a 29 [2] 65 33 [2] 7b 2e [2] 79 2f [2] 62 29 [2] 7e 2e [2] 62 01 }

  condition:
    any of them
}