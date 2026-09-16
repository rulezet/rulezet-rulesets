rule TTP_XOR_QUAD_CurrentVersionRun_727b {
  strings:
    $key_727b = { 21 14 [2] 05 1a [2] 2e 36 [2] 00 14 [2] 14 0f [2] 1b 15 [2] 05 08 [2] 07 09 [2] 1c 0f [2] 00 08 [2] 1c 27 }

  condition:
    any of them
}