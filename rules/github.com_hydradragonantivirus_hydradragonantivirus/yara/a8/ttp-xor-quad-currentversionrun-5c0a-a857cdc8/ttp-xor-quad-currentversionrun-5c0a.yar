rule TTP_XOR_QUAD_CurrentVersionRun_5c0a {
  strings:
    $key_5c0a = { 0f 65 [2] 2b 6b [2] 00 47 [2] 2e 65 [2] 3a 7e [2] 35 64 [2] 2b 79 [2] 29 78 [2] 32 7e [2] 2e 79 [2] 32 56 }

  condition:
    any of them
}