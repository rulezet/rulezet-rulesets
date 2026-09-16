rule TTP_XOR_QUAD_CurrentVersionRun_772f {
  strings:
    $key_772f = { 24 40 [2] 00 4e [2] 2b 62 [2] 05 40 [2] 11 5b [2] 1e 41 [2] 00 5c [2] 02 5d [2] 19 5b [2] 05 5c [2] 19 73 }

  condition:
    any of them
}