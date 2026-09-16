rule TTP_XOR_QUAD_CurrentVersionRun_7d5c {
  strings:
    $key_7d5c = { 2e 33 [2] 0a 3d [2] 21 11 [2] 0f 33 [2] 1b 28 [2] 14 32 [2] 0a 2f [2] 08 2e [2] 13 28 [2] 0f 2f [2] 13 00 }

  condition:
    any of them
}