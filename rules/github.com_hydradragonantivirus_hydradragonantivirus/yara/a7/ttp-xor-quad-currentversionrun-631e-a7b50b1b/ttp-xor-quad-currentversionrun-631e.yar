rule TTP_XOR_QUAD_CurrentVersionRun_631e {
  strings:
    $key_631e = { 30 71 [2] 14 7f [2] 3f 53 [2] 11 71 [2] 05 6a [2] 0a 70 [2] 14 6d [2] 16 6c [2] 0d 6a [2] 11 6d [2] 0d 42 }

  condition:
    any of them
}