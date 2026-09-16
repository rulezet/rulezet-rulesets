rule TTP_XOR_QUAD_CurrentVersionRun_1b19 {
  strings:
    $key_1b19 = { 48 76 [2] 6c 78 [2] 47 54 [2] 69 76 [2] 7d 6d [2] 72 77 [2] 6c 6a [2] 6e 6b [2] 75 6d [2] 69 6a [2] 75 45 }

  condition:
    any of them
}