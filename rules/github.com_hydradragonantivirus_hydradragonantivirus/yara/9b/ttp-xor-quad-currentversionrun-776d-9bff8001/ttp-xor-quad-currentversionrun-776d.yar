rule TTP_XOR_QUAD_CurrentVersionRun_776d {
  strings:
    $key_776d = { 24 02 [2] 00 0c [2] 2b 20 [2] 05 02 [2] 11 19 [2] 1e 03 [2] 00 1e [2] 02 1f [2] 19 19 [2] 05 1e [2] 19 31 }

  condition:
    any of them
}