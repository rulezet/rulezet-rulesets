rule TTP_XOR_QUAD_CurrentVersionRun_4d38 {
  strings:
    $key_4d38 = { 1e 57 [2] 3a 59 [2] 11 75 [2] 3f 57 [2] 2b 4c [2] 24 56 [2] 3a 4b [2] 38 4a [2] 23 4c [2] 3f 4b [2] 23 64 }

  condition:
    any of them
}