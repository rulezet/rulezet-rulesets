rule TTP_XOR_QUAD_CurrentVersionRun_0e5d {
  strings:
    $key_0e5d = { 5d 32 [2] 79 3c [2] 52 10 [2] 7c 32 [2] 68 29 [2] 67 33 [2] 79 2e [2] 7b 2f [2] 60 29 [2] 7c 2e [2] 60 01 }

  condition:
    any of them
}