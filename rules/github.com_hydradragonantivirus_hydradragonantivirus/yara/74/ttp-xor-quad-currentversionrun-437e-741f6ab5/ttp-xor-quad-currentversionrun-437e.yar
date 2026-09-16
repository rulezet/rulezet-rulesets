rule TTP_XOR_QUAD_CurrentVersionRun_437e {
  strings:
    $key_437e = { 10 11 [2] 34 1f [2] 1f 33 [2] 31 11 [2] 25 0a [2] 2a 10 [2] 34 0d [2] 36 0c [2] 2d 0a [2] 31 0d [2] 2d 22 }

  condition:
    any of them
}