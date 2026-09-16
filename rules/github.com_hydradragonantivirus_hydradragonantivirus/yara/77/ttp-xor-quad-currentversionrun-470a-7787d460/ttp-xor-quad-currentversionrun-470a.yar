rule TTP_XOR_QUAD_CurrentVersionRun_470a {
  strings:
    $key_470a = { 14 65 [2] 30 6b [2] 1b 47 [2] 35 65 [2] 21 7e [2] 2e 64 [2] 30 79 [2] 32 78 [2] 29 7e [2] 35 79 [2] 29 56 }

  condition:
    any of them
}