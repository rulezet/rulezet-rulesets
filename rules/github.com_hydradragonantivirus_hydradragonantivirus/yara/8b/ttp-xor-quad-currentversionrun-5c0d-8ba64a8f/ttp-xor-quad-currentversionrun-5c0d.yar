rule TTP_XOR_QUAD_CurrentVersionRun_5c0d {
  strings:
    $key_5c0d = { 0f 62 [2] 2b 6c [2] 00 40 [2] 2e 62 [2] 3a 79 [2] 35 63 [2] 2b 7e [2] 29 7f [2] 32 79 [2] 2e 7e [2] 32 51 }

  condition:
    any of them
}