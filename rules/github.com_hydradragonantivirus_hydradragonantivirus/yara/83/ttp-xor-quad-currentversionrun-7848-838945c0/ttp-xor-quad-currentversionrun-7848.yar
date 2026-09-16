rule TTP_XOR_QUAD_CurrentVersionRun_7848 {
  strings:
    $key_7848 = { 2b 27 [2] 0f 29 [2] 24 05 [2] 0a 27 [2] 1e 3c [2] 11 26 [2] 0f 3b [2] 0d 3a [2] 16 3c [2] 0a 3b [2] 16 14 }

  condition:
    any of them
}