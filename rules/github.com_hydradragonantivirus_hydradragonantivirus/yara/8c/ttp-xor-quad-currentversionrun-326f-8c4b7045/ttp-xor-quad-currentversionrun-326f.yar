rule TTP_XOR_QUAD_CurrentVersionRun_326f {
  strings:
    $key_326f = { 61 00 [2] 45 0e [2] 6e 22 [2] 40 00 [2] 54 1b [2] 5b 01 [2] 45 1c [2] 47 1d [2] 5c 1b [2] 40 1c [2] 5c 33 }

  condition:
    any of them
}