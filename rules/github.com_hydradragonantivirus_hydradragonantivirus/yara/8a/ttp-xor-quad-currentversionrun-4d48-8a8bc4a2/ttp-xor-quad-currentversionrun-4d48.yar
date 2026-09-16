rule TTP_XOR_QUAD_CurrentVersionRun_4d48 {
  strings:
    $key_4d48 = { 1e 27 [2] 3a 29 [2] 11 05 [2] 3f 27 [2] 2b 3c [2] 24 26 [2] 3a 3b [2] 38 3a [2] 23 3c [2] 3f 3b [2] 23 14 }

  condition:
    any of them
}