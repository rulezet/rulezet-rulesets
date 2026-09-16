rule TTP_XOR_QUAD_CurrentVersionRun_5c3f {
  strings:
    $key_5c3f = { 0f 50 [2] 2b 5e [2] 00 72 [2] 2e 50 [2] 3a 4b [2] 35 51 [2] 2b 4c [2] 29 4d [2] 32 4b [2] 2e 4c [2] 32 63 }

  condition:
    any of them
}