rule TTP_XOR_QUAD_CurrentVersionRun_5f2e {
  strings:
    $key_5f2e = { 0c 41 [2] 28 4f [2] 03 63 [2] 2d 41 [2] 39 5a [2] 36 40 [2] 28 5d [2] 2a 5c [2] 31 5a [2] 2d 5d [2] 31 72 }

  condition:
    any of them
}