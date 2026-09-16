rule TTP_XOR_QUAD_CurrentVersionRun_3e5d {
  strings:
    $key_3e5d = { 6d 32 [2] 49 3c [2] 62 10 [2] 4c 32 [2] 58 29 [2] 57 33 [2] 49 2e [2] 4b 2f [2] 50 29 [2] 4c 2e [2] 50 01 }

  condition:
    any of them
}