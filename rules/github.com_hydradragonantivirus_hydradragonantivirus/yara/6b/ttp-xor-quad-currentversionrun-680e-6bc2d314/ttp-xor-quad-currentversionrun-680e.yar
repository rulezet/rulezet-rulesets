rule TTP_XOR_QUAD_CurrentVersionRun_680e {
  strings:
    $key_680e = { 3b 61 [2] 1f 6f [2] 34 43 [2] 1a 61 [2] 0e 7a [2] 01 60 [2] 1f 7d [2] 1d 7c [2] 06 7a [2] 1a 7d [2] 06 52 }

  condition:
    any of them
}