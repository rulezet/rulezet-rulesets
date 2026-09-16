rule TTP_XOR_QUAD_CurrentVersionRun_417e {
  strings:
    $key_417e = { 12 11 [2] 36 1f [2] 1d 33 [2] 33 11 [2] 27 0a [2] 28 10 [2] 36 0d [2] 34 0c [2] 2f 0a [2] 33 0d [2] 2f 22 }

  condition:
    any of them
}