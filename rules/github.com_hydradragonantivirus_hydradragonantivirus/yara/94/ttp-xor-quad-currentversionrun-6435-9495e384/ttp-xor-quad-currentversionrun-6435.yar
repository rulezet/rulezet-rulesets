rule TTP_XOR_QUAD_CurrentVersionRun_6435 {
  strings:
    $key_6435 = { 37 5a [2] 13 54 [2] 38 78 [2] 16 5a [2] 02 41 [2] 0d 5b [2] 13 46 [2] 11 47 [2] 0a 41 [2] 16 46 [2] 0a 69 }

  condition:
    any of them
}