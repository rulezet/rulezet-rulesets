rule TTP_XOR_QUAD_CurrentVersionRun_690a {
  strings:
    $key_690a = { 3a 65 [2] 1e 6b [2] 35 47 [2] 1b 65 [2] 0f 7e [2] 00 64 [2] 1e 79 [2] 1c 78 [2] 07 7e [2] 1b 79 [2] 07 56 }

  condition:
    any of them
}