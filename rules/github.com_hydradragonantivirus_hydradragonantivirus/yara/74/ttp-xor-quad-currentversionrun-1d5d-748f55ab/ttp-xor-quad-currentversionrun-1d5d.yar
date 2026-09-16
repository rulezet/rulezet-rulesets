rule TTP_XOR_QUAD_CurrentVersionRun_1d5d {
  strings:
    $key_1d5d = { 4e 32 [2] 6a 3c [2] 41 10 [2] 6f 32 [2] 7b 29 [2] 74 33 [2] 6a 2e [2] 68 2f [2] 73 29 [2] 6f 2e [2] 73 01 }

  condition:
    any of them
}