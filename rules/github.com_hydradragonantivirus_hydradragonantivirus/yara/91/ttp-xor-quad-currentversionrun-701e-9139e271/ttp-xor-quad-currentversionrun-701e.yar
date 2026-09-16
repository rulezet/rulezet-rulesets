rule TTP_XOR_QUAD_CurrentVersionRun_701e {
  strings:
    $key_701e = { 23 71 [2] 07 7f [2] 2c 53 [2] 02 71 [2] 16 6a [2] 19 70 [2] 07 6d [2] 05 6c [2] 1e 6a [2] 02 6d [2] 1e 42 }

  condition:
    any of them
}