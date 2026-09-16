rule TTP_XOR_QUAD_CurrentVersionRun_6f1e {
  strings:
    $key_6f1e = { 3c 71 [2] 18 7f [2] 33 53 [2] 1d 71 [2] 09 6a [2] 06 70 [2] 18 6d [2] 1a 6c [2] 01 6a [2] 1d 6d [2] 01 42 }

  condition:
    any of them
}