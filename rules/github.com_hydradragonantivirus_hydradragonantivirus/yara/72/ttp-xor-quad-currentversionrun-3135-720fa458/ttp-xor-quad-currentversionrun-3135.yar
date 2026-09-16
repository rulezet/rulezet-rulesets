rule TTP_XOR_QUAD_CurrentVersionRun_3135 {
  strings:
    $key_3135 = { 62 5a [2] 46 54 [2] 6d 78 [2] 43 5a [2] 57 41 [2] 58 5b [2] 46 46 [2] 44 47 [2] 5f 41 [2] 43 46 [2] 5f 69 }

  condition:
    any of them
}