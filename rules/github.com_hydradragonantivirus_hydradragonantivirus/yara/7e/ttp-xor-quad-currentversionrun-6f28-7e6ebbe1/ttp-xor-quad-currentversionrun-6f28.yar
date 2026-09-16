rule TTP_XOR_QUAD_CurrentVersionRun_6f28 {
  strings:
    $key_6f28 = { 3c 47 [2] 18 49 [2] 33 65 [2] 1d 47 [2] 09 5c [2] 06 46 [2] 18 5b [2] 1a 5a [2] 01 5c [2] 1d 5b [2] 01 74 }

  condition:
    any of them
}