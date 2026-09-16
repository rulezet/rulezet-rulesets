rule TTP_XOR_QUAD_CurrentVersionRun_5f0e {
  strings:
    $key_5f0e = { 0c 61 [2] 28 6f [2] 03 43 [2] 2d 61 [2] 39 7a [2] 36 60 [2] 28 7d [2] 2a 7c [2] 31 7a [2] 2d 7d [2] 31 52 }

  condition:
    any of them
}