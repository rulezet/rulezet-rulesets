rule TTP_XOR_QUAD_CurrentVersionRun_5cfb {
  strings:
    $key_5cfb = { 0f 94 [2] 2b 9a [2] 00 b6 [2] 2e 94 [2] 3a 8f [2] 35 95 [2] 2b 88 [2] 29 89 [2] 32 8f [2] 2e 88 [2] 32 a7 }

  condition:
    any of them
}