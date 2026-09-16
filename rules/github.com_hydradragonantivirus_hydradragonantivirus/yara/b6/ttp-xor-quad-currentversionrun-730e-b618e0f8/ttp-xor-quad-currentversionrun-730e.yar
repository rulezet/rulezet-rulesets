rule TTP_XOR_QUAD_CurrentVersionRun_730e {
  strings:
    $key_730e = { 20 61 [2] 04 6f [2] 2f 43 [2] 01 61 [2] 15 7a [2] 1a 60 [2] 04 7d [2] 06 7c [2] 1d 7a [2] 01 7d [2] 1d 52 }

  condition:
    any of them
}