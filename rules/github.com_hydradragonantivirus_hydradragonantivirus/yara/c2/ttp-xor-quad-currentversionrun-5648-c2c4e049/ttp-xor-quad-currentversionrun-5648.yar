rule TTP_XOR_QUAD_CurrentVersionRun_5648 {
  strings:
    $key_5648 = { 05 27 [2] 21 29 [2] 0a 05 [2] 24 27 [2] 30 3c [2] 3f 26 [2] 21 3b [2] 23 3a [2] 38 3c [2] 24 3b [2] 38 14 }

  condition:
    any of them
}