rule TTP_XOR_QUAD_CurrentVersionRun_6966 {
  strings:
    $key_6966 = { 3a 09 [2] 1e 07 [2] 35 2b [2] 1b 09 [2] 0f 12 [2] 00 08 [2] 1e 15 [2] 1c 14 [2] 07 12 [2] 1b 15 [2] 07 3a }

  condition:
    any of them
}