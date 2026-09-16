rule TTP_XOR_QUAD_CurrentVersionRun_7d5d {
  strings:
    $key_7d5d = { 2e 32 [2] 0a 3c [2] 21 10 [2] 0f 32 [2] 1b 29 [2] 14 33 [2] 0a 2e [2] 08 2f [2] 13 29 [2] 0f 2e [2] 13 01 }

  condition:
    any of them
}