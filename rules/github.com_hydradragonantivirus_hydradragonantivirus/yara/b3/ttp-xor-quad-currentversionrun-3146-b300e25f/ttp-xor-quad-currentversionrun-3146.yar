rule TTP_XOR_QUAD_CurrentVersionRun_3146 {
  strings:
    $key_3146 = { 62 29 [2] 46 27 [2] 6d 0b [2] 43 29 [2] 57 32 [2] 58 28 [2] 46 35 [2] 44 34 [2] 5f 32 [2] 43 35 [2] 5f 1a }

  condition:
    any of them
}