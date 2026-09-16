rule TTP_XOR_QUAD_CurrentVersionRun_757f {
  strings:
    $key_757f = { 26 10 [2] 02 1e [2] 29 32 [2] 07 10 [2] 13 0b [2] 1c 11 [2] 02 0c [2] 00 0d [2] 1b 0b [2] 07 0c [2] 1b 23 }

  condition:
    any of them
}