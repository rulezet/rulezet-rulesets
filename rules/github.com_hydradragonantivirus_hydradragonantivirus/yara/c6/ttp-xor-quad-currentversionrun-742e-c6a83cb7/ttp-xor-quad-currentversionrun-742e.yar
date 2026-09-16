rule TTP_XOR_QUAD_CurrentVersionRun_742e {
  strings:
    $key_742e = { 27 41 [2] 03 4f [2] 28 63 [2] 06 41 [2] 12 5a [2] 1d 40 [2] 03 5d [2] 01 5c [2] 1a 5a [2] 06 5d [2] 1a 72 }

  condition:
    any of them
}