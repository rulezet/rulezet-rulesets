rule TTP_XOR_QUAD_CurrentVersionRun_691d {
  strings:
    $key_691d = { 3a 72 [2] 1e 7c [2] 35 50 [2] 1b 72 [2] 0f 69 [2] 00 73 [2] 1e 6e [2] 1c 6f [2] 07 69 [2] 1b 6e [2] 07 41 }

  condition:
    any of them
}