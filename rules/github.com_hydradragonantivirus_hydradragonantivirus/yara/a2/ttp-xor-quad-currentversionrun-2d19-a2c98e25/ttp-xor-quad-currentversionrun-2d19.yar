rule TTP_XOR_QUAD_CurrentVersionRun_2d19 {
  strings:
    $key_2d19 = { 7e 76 [2] 5a 78 [2] 71 54 [2] 5f 76 [2] 4b 6d [2] 44 77 [2] 5a 6a [2] 58 6b [2] 43 6d [2] 5f 6a [2] 43 45 }

  condition:
    any of them
}