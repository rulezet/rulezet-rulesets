rule TTP_XOR_QUAD_CurrentVersionRun_6a0e {
  strings:
    $key_6a0e = { 39 61 [2] 1d 6f [2] 36 43 [2] 18 61 [2] 0c 7a [2] 03 60 [2] 1d 7d [2] 1f 7c [2] 04 7a [2] 18 7d [2] 04 52 }

  condition:
    any of them
}