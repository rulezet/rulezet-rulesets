rule TTP_XOR_QUAD_CurrentVersionRun_757c {
  strings:
    $key_757c = { 26 13 [2] 02 1d [2] 29 31 [2] 07 13 [2] 13 08 [2] 1c 12 [2] 02 0f [2] 00 0e [2] 1b 08 [2] 07 0f [2] 1b 20 }

  condition:
    any of them
}