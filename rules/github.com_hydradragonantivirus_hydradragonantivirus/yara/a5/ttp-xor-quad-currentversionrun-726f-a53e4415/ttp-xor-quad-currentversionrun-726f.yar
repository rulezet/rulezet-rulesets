rule TTP_XOR_QUAD_CurrentVersionRun_726f {
  strings:
    $key_726f = { 21 00 [2] 05 0e [2] 2e 22 [2] 00 00 [2] 14 1b [2] 1b 01 [2] 05 1c [2] 07 1d [2] 1c 1b [2] 00 1c [2] 1c 33 }

  condition:
    any of them
}