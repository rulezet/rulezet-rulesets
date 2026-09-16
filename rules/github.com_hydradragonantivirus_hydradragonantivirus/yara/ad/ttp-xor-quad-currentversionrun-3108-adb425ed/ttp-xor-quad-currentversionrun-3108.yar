rule TTP_XOR_QUAD_CurrentVersionRun_3108 {
  strings:
    $key_3108 = { 62 67 [2] 46 69 [2] 6d 45 [2] 43 67 [2] 57 7c [2] 58 66 [2] 46 7b [2] 44 7a [2] 5f 7c [2] 43 7b [2] 5f 54 }

  condition:
    any of them
}