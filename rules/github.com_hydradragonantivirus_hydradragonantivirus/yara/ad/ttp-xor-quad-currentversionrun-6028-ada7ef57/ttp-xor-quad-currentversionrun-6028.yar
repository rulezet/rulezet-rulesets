rule TTP_XOR_QUAD_CurrentVersionRun_6028 {
  strings:
    $key_6028 = { 33 47 [2] 17 49 [2] 3c 65 [2] 12 47 [2] 06 5c [2] 09 46 [2] 17 5b [2] 15 5a [2] 0e 5c [2] 12 5b [2] 0e 74 }

  condition:
    any of them
}