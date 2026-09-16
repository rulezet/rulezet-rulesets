rule TTP_XOR_QUAD_CurrentVersionRun_4d28 {
  strings:
    $key_4d28 = { 1e 47 [2] 3a 49 [2] 11 65 [2] 3f 47 [2] 2b 5c [2] 24 46 [2] 3a 5b [2] 38 5a [2] 23 5c [2] 3f 5b [2] 23 74 }

  condition:
    any of them
}