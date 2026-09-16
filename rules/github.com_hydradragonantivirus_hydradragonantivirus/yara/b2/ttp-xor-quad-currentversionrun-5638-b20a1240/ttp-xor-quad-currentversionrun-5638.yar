rule TTP_XOR_QUAD_CurrentVersionRun_5638 {
  strings:
    $key_5638 = { 05 57 [2] 21 59 [2] 0a 75 [2] 24 57 [2] 30 4c [2] 3f 56 [2] 21 4b [2] 23 4a [2] 38 4c [2] 24 4b [2] 38 64 }

  condition:
    any of them
}