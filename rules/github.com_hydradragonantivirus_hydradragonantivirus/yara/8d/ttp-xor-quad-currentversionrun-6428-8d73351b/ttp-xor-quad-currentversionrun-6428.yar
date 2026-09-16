rule TTP_XOR_QUAD_CurrentVersionRun_6428 {
  strings:
    $key_6428 = { 37 47 [2] 13 49 [2] 38 65 [2] 16 47 [2] 02 5c [2] 0d 46 [2] 13 5b [2] 11 5a [2] 0a 5c [2] 16 5b [2] 0a 74 }

  condition:
    any of them
}