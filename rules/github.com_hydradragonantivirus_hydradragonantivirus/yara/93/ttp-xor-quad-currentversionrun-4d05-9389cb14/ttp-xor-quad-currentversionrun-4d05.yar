rule TTP_XOR_QUAD_CurrentVersionRun_4d05 {
  strings:
    $key_4d05 = { 1e 6a [2] 3a 64 [2] 11 48 [2] 3f 6a [2] 2b 71 [2] 24 6b [2] 3a 76 [2] 38 77 [2] 23 71 [2] 3f 76 [2] 23 59 }

  condition:
    any of them
}