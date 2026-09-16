rule TTP_XOR_QUAD_CurrentVersionRun_2868 {
  strings:
    $key_2868 = { 7b 07 [2] 5f 09 [2] 74 25 [2] 5a 07 [2] 4e 1c [2] 41 06 [2] 5f 1b [2] 5d 1a [2] 46 1c [2] 5a 1b [2] 46 34 }

  condition:
    any of them
}