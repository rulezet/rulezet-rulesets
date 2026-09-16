rule TTP_XOR_QUAD_CurrentVersionRun_731e {
  strings:
    $key_731e = { 20 71 [2] 04 7f [2] 2f 53 [2] 01 71 [2] 15 6a [2] 1a 70 [2] 04 6d [2] 06 6c [2] 1d 6a [2] 01 6d [2] 1d 42 }

  condition:
    any of them
}