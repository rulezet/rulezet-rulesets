rule TTP_XOR_QUAD_CurrentVersionRun_3e45 {
  strings:
    $key_3e45 = { 6d 2a [2] 49 24 [2] 62 08 [2] 4c 2a [2] 58 31 [2] 57 2b [2] 49 36 [2] 4b 37 [2] 50 31 [2] 4c 36 [2] 50 19 }

  condition:
    any of them
}