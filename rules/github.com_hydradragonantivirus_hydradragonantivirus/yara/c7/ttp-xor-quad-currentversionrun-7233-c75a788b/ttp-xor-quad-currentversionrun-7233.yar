rule TTP_XOR_QUAD_CurrentVersionRun_7233 {
  strings:
    $key_7233 = { 21 5c [2] 05 52 [2] 2e 7e [2] 00 5c [2] 14 47 [2] 1b 5d [2] 05 40 [2] 07 41 [2] 1c 47 [2] 00 40 [2] 1c 6f }

  condition:
    any of them
}