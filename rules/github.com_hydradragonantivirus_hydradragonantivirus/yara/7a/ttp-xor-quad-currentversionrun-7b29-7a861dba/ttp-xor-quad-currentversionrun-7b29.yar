rule TTP_XOR_QUAD_CurrentVersionRun_7b29 {
  strings:
    $key_7b29 = { 28 46 [2] 0c 48 [2] 27 64 [2] 09 46 [2] 1d 5d [2] 12 47 [2] 0c 5a [2] 0e 5b [2] 15 5d [2] 09 5a [2] 15 75 }

  condition:
    any of them
}