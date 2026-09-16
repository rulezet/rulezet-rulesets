rule TTP_XOR_QUAD_CurrentVersionRun_727c {
  strings:
    $key_727c = { 21 13 [2] 05 1d [2] 2e 31 [2] 00 13 [2] 14 08 [2] 1b 12 [2] 05 0f [2] 07 0e [2] 1c 08 [2] 00 0f [2] 1c 20 }

  condition:
    any of them
}