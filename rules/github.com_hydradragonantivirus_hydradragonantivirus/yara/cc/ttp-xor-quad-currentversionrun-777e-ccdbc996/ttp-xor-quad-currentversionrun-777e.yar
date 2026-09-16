rule TTP_XOR_QUAD_CurrentVersionRun_777e {
  strings:
    $key_777e = { 24 11 [2] 00 1f [2] 2b 33 [2] 05 11 [2] 11 0a [2] 1e 10 [2] 00 0d [2] 02 0c [2] 19 0a [2] 05 0d [2] 19 22 }

  condition:
    any of them
}