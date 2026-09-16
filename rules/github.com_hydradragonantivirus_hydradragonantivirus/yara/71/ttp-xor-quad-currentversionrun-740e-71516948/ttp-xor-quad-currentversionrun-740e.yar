rule TTP_XOR_QUAD_CurrentVersionRun_740e {
  strings:
    $key_740e = { 27 61 [2] 03 6f [2] 28 43 [2] 06 61 [2] 12 7a [2] 1d 60 [2] 03 7d [2] 01 7c [2] 1a 7a [2] 06 7d [2] 1a 52 }

  condition:
    any of them
}