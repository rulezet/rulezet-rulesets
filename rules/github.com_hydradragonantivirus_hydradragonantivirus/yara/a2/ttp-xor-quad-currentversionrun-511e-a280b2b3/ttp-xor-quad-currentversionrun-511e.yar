rule TTP_XOR_QUAD_CurrentVersionRun_511e {
  strings:
    $key_511e = { 02 71 [2] 26 7f [2] 0d 53 [2] 23 71 [2] 37 6a [2] 38 70 [2] 26 6d [2] 24 6c [2] 3f 6a [2] 23 6d [2] 3f 42 }

  condition:
    any of them
}