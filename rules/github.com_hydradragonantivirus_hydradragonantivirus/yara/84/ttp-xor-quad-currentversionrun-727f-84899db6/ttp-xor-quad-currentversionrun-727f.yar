rule TTP_XOR_QUAD_CurrentVersionRun_727f {
  strings:
    $key_727f = { 21 10 [2] 05 1e [2] 2e 32 [2] 00 10 [2] 14 0b [2] 1b 11 [2] 05 0c [2] 07 0d [2] 1c 0b [2] 00 0c [2] 1c 23 }

  condition:
    any of them
}