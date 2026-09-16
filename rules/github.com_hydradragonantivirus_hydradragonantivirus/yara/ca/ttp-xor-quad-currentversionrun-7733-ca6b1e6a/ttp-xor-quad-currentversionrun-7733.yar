rule TTP_XOR_QUAD_CurrentVersionRun_7733 {
  strings:
    $key_7733 = { 24 5c [2] 00 52 [2] 2b 7e [2] 05 5c [2] 11 47 [2] 1e 5d [2] 00 40 [2] 02 41 [2] 19 47 [2] 05 40 [2] 19 6f }

  condition:
    any of them
}