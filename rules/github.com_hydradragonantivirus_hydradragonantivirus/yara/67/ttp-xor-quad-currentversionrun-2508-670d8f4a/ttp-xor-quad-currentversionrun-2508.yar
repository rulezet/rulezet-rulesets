rule TTP_XOR_QUAD_CurrentVersionRun_2508 {
  strings:
    $key_2508 = { 76 67 [2] 52 69 [2] 79 45 [2] 57 67 [2] 43 7c [2] 4c 66 [2] 52 7b [2] 50 7a [2] 4b 7c [2] 57 7b [2] 4b 54 }

  condition:
    any of them
}