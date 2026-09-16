rule TTP_XOR_QUAD_CurrentVersionRun_0b19 {
  strings:
    $key_0b19 = { 58 76 [2] 7c 78 [2] 57 54 [2] 79 76 [2] 6d 6d [2] 62 77 [2] 7c 6a [2] 7e 6b [2] 65 6d [2] 79 6a [2] 65 45 }

  condition:
    any of them
}