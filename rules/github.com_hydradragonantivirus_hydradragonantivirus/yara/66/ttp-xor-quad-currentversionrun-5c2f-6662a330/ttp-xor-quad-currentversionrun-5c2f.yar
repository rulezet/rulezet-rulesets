rule TTP_XOR_QUAD_CurrentVersionRun_5c2f {
  strings:
    $key_5c2f = { 0f 40 [2] 2b 4e [2] 00 62 [2] 2e 40 [2] 3a 5b [2] 35 41 [2] 2b 5c [2] 29 5d [2] 32 5b [2] 2e 5c [2] 32 73 }

  condition:
    any of them
}