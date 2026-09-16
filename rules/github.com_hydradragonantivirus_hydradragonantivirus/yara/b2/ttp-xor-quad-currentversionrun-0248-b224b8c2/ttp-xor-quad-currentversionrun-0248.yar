rule TTP_XOR_QUAD_CurrentVersionRun_0248 {
  strings:
    $key_0248 = { 51 27 [2] 75 29 [2] 5e 05 [2] 70 27 [2] 64 3c [2] 6b 26 [2] 75 3b [2] 77 3a [2] 6c 3c [2] 70 3b [2] 6c 14 }

  condition:
    any of them
}