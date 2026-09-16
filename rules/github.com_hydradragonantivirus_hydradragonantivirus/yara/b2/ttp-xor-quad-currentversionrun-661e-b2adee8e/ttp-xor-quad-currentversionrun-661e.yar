rule TTP_XOR_QUAD_CurrentVersionRun_661e {
  strings:
    $key_661e = { 35 71 [2] 11 7f [2] 3a 53 [2] 14 71 [2] 00 6a [2] 0f 70 [2] 11 6d [2] 13 6c [2] 08 6a [2] 14 6d [2] 08 42 }

  condition:
    any of them
}