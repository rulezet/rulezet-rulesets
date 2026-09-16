rule TTP_XOR_QUAD_CurrentVersionRun_2b19 {
  strings:
    $key_2b19 = { 78 76 [2] 5c 78 [2] 77 54 [2] 59 76 [2] 4d 6d [2] 42 77 [2] 5c 6a [2] 5e 6b [2] 45 6d [2] 59 6a [2] 45 45 }

  condition:
    any of them
}