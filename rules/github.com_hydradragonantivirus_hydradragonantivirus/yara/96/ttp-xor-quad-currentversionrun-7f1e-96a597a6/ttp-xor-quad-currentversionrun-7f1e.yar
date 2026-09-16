rule TTP_XOR_QUAD_CurrentVersionRun_7f1e {
  strings:
    $key_7f1e = { 2c 71 [2] 08 7f [2] 23 53 [2] 0d 71 [2] 19 6a [2] 16 70 [2] 08 6d [2] 0a 6c [2] 11 6a [2] 0d 6d [2] 11 42 }

  condition:
    any of them
}