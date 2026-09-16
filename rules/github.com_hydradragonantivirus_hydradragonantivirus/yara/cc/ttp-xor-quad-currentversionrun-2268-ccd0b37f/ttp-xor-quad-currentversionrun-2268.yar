rule TTP_XOR_QUAD_CurrentVersionRun_2268 {
  strings:
    $key_2268 = { 71 07 [2] 55 09 [2] 7e 25 [2] 50 07 [2] 44 1c [2] 4b 06 [2] 55 1b [2] 57 1a [2] 4c 1c [2] 50 1b [2] 4c 34 }

  condition:
    any of them
}