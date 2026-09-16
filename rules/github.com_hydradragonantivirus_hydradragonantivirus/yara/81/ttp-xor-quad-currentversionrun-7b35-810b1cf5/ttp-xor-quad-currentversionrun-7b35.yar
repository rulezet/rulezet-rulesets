rule TTP_XOR_QUAD_CurrentVersionRun_7b35 {
  strings:
    $key_7b35 = { 28 5a [2] 0c 54 [2] 27 78 [2] 09 5a [2] 1d 41 [2] 12 5b [2] 0c 46 [2] 0e 47 [2] 15 41 [2] 09 46 [2] 15 69 }

  condition:
    any of them
}