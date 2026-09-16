rule TTP_XOR_QUAD_CurrentVersionRun_772e {
  strings:
    $key_772e = { 24 41 [2] 00 4f [2] 2b 63 [2] 05 41 [2] 11 5a [2] 1e 40 [2] 00 5d [2] 02 5c [2] 19 5a [2] 05 5d [2] 19 72 }

  condition:
    any of them
}