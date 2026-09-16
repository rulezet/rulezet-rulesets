rule TTP_XOR_QUAD_CurrentVersionRun_7529 {
  strings:
    $key_7529 = { 26 46 [2] 02 48 [2] 29 64 [2] 07 46 [2] 13 5d [2] 1c 47 [2] 02 5a [2] 00 5b [2] 1b 5d [2] 07 5a [2] 1b 75 }

  condition:
    any of them
}