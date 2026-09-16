rule TTP_XOR_QUAD_CurrentVersionRun_5cee {
  strings:
    $key_5cee = { 0f 81 [2] 2b 8f [2] 00 a3 [2] 2e 81 [2] 3a 9a [2] 35 80 [2] 2b 9d [2] 29 9c [2] 32 9a [2] 2e 9d [2] 32 b2 }

  condition:
    any of them
}