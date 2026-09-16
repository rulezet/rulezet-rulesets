rule TTP_XOR_QUAD_CurrentVersionRun_4d0e {
  strings:
    $key_4d0e = { 1e 61 [2] 3a 6f [2] 11 43 [2] 3f 61 [2] 2b 7a [2] 24 60 [2] 3a 7d [2] 38 7c [2] 23 7a [2] 3f 7d [2] 23 52 }

  condition:
    any of them
}