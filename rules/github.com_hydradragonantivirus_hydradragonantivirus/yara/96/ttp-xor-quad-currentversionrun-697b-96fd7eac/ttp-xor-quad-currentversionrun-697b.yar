rule TTP_XOR_QUAD_CurrentVersionRun_697b {
  strings:
    $key_697b = { 3a 14 [2] 1e 1a [2] 35 36 [2] 1b 14 [2] 0f 0f [2] 00 15 [2] 1e 08 [2] 1c 09 [2] 07 0f [2] 1b 08 [2] 07 27 }

  condition:
    any of them
}