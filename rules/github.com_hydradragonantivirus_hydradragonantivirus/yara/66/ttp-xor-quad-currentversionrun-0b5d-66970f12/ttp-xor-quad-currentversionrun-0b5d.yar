rule TTP_XOR_QUAD_CurrentVersionRun_0b5d {
  strings:
    $key_0b5d = { 58 32 [2] 7c 3c [2] 57 10 [2] 79 32 [2] 6d 29 [2] 62 33 [2] 7c 2e [2] 7e 2f [2] 65 29 [2] 79 2e [2] 65 01 }

  condition:
    any of them
}