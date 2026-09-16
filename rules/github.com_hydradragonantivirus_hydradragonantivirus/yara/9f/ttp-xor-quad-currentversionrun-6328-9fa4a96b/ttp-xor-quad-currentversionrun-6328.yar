rule TTP_XOR_QUAD_CurrentVersionRun_6328 {
  strings:
    $key_6328 = { 30 47 [2] 14 49 [2] 3f 65 [2] 11 47 [2] 05 5c [2] 0a 46 [2] 14 5b [2] 16 5a [2] 0d 5c [2] 11 5b [2] 0d 74 }

  condition:
    any of them
}