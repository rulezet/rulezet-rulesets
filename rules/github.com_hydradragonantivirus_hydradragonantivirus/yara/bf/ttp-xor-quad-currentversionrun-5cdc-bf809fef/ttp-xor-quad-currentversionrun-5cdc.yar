rule TTP_XOR_QUAD_CurrentVersionRun_5cdc {
  strings:
    $key_5cdc = { 0f b3 [2] 2b bd [2] 00 91 [2] 2e b3 [2] 3a a8 [2] 35 b2 [2] 2b af [2] 29 ae [2] 32 a8 [2] 2e af [2] 32 80 }

  condition:
    any of them
}