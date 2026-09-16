rule TTP_XOR_QUAD_CurrentVersionRun_600e {
  strings:
    $key_600e = { 33 61 [2] 17 6f [2] 3c 43 [2] 12 61 [2] 06 7a [2] 09 60 [2] 17 7d [2] 15 7c [2] 0e 7a [2] 12 7d [2] 0e 52 }

  condition:
    any of them
}