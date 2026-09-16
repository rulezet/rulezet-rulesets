rule TTP_XOR_QUAD_CurrentVersionRun_772d {
  strings:
    $key_772d = { 24 42 [2] 00 4c [2] 2b 60 [2] 05 42 [2] 11 59 [2] 1e 43 [2] 00 5e [2] 02 5f [2] 19 59 [2] 05 5e [2] 19 71 }

  condition:
    any of them
}