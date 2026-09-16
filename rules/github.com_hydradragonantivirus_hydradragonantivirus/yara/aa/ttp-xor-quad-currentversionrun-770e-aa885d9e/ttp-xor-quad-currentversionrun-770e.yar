rule TTP_XOR_QUAD_CurrentVersionRun_770e {
  strings:
    $key_770e = { 24 61 [2] 00 6f [2] 2b 43 [2] 05 61 [2] 11 7a [2] 1e 60 [2] 00 7d [2] 02 7c [2] 19 7a [2] 05 7d [2] 19 52 }

  condition:
    any of them
}