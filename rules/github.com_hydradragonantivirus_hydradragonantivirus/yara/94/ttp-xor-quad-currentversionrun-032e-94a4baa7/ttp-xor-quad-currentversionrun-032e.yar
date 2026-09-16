rule TTP_XOR_QUAD_CurrentVersionRun_032e {
  strings:
    $key_032e = { 50 41 [2] 74 4f [2] 5f 63 [2] 71 41 [2] 65 5a [2] 6a 40 [2] 74 5d [2] 76 5c [2] 6d 5a [2] 71 5d [2] 6d 72 }

  condition:
    any of them
}