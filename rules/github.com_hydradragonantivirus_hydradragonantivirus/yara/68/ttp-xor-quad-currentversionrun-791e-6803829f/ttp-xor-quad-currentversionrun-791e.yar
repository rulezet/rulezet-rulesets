rule TTP_XOR_QUAD_CurrentVersionRun_791e {
  strings:
    $key_791e = { 2a 71 [2] 0e 7f [2] 25 53 [2] 0b 71 [2] 1f 6a [2] 10 70 [2] 0e 6d [2] 0c 6c [2] 17 6a [2] 0b 6d [2] 17 42 }

  condition:
    any of them
}