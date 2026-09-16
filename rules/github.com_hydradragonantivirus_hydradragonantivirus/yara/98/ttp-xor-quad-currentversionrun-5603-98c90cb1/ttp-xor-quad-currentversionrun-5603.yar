rule TTP_XOR_QUAD_CurrentVersionRun_5603 {
  strings:
    $key_5603 = { 05 6c [2] 21 62 [2] 0a 4e [2] 24 6c [2] 30 77 [2] 3f 6d [2] 21 70 [2] 23 71 [2] 38 77 [2] 24 70 [2] 38 5f }

  condition:
    any of them
}