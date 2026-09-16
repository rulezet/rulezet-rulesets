rule TTP_XOR_QUAD_CurrentVersionRun_2568 {
  strings:
    $key_2568 = { 76 07 [2] 52 09 [2] 79 25 [2] 57 07 [2] 43 1c [2] 4c 06 [2] 52 1b [2] 50 1a [2] 4b 1c [2] 57 1b [2] 4b 34 }

  condition:
    any of them
}