rule TTP_XOR_QUAD_CurrentVersionRun_6619 {
  strings:
    $key_6619 = { 35 76 [2] 11 78 [2] 3a 54 [2] 14 76 [2] 00 6d [2] 0f 77 [2] 11 6a [2] 13 6b [2] 08 6d [2] 14 6a [2] 08 45 }

  condition:
    any of them
}