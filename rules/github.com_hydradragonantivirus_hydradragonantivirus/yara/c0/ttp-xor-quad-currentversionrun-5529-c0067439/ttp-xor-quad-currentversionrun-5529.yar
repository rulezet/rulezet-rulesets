rule TTP_XOR_QUAD_CurrentVersionRun_5529 {
  strings:
    $key_5529 = { 06 46 [2] 22 48 [2] 09 64 [2] 27 46 [2] 33 5d [2] 3c 47 [2] 22 5a [2] 20 5b [2] 3b 5d [2] 27 5a [2] 3b 75 }

  condition:
    any of them
}