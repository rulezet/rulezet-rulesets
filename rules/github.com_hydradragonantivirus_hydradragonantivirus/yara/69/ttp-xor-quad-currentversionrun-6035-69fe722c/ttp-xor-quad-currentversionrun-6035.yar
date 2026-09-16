rule TTP_XOR_QUAD_CurrentVersionRun_6035 {
  strings:
    $key_6035 = { 33 5a [2] 17 54 [2] 3c 78 [2] 12 5a [2] 06 41 [2] 09 5b [2] 17 46 [2] 15 47 [2] 0e 41 [2] 12 46 [2] 0e 69 }

  condition:
    any of them
}