rule TTP_XOR_QUAD_CurrentVersionRun_641e {
  strings:
    $key_641e = { 37 71 [2] 13 7f [2] 38 53 [2] 16 71 [2] 02 6a [2] 0d 70 [2] 13 6d [2] 11 6c [2] 0a 6a [2] 16 6d [2] 0a 42 }

  condition:
    any of them
}