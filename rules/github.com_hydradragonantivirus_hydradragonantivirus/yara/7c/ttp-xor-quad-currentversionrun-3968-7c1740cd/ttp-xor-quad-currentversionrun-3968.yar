rule TTP_XOR_QUAD_CurrentVersionRun_3968 {
  strings:
    $key_3968 = { 6a 07 [2] 4e 09 [2] 65 25 [2] 4b 07 [2] 5f 1c [2] 50 06 [2] 4e 1b [2] 4c 1a [2] 57 1c [2] 4b 1b [2] 57 34 }

  condition:
    any of them
}