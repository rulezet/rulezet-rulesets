rule TTP_XOR_QUAD_CurrentVersionRun_5c3e {
  strings:
    $key_5c3e = { 0f 51 [2] 2b 5f [2] 00 73 [2] 2e 51 [2] 3a 4a [2] 35 50 [2] 2b 4d [2] 29 4c [2] 32 4a [2] 2e 4d [2] 32 62 }

  condition:
    any of them
}