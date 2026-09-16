rule TTP_XOR_QUAD_CurrentVersionRun_5c3c {
  strings:
    $key_5c3c = { 0f 53 [2] 2b 5d [2] 00 71 [2] 2e 53 [2] 3a 48 [2] 35 52 [2] 2b 4f [2] 29 4e [2] 32 48 [2] 2e 4f [2] 32 60 }

  condition:
    any of them
}