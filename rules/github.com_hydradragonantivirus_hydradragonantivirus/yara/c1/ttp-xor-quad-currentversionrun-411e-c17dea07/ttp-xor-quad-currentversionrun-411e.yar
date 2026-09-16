rule TTP_XOR_QUAD_CurrentVersionRun_411e {
  strings:
    $key_411e = { 12 71 [2] 36 7f [2] 1d 53 [2] 33 71 [2] 27 6a [2] 28 70 [2] 36 6d [2] 34 6c [2] 2f 6a [2] 33 6d [2] 2f 42 }

  condition:
    any of them
}