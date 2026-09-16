rule TTP_XOR_QUAD_CurrentVersionRun_7b45 {
  strings:
    $key_7b45 = { 28 2a [2] 0c 24 [2] 27 08 [2] 09 2a [2] 1d 31 [2] 12 2b [2] 0c 36 [2] 0e 37 [2] 15 31 [2] 09 36 [2] 15 19 }

  condition:
    any of them
}