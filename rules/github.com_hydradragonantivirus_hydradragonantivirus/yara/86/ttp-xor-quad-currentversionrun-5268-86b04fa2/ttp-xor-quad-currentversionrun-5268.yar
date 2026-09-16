rule TTP_XOR_QUAD_CurrentVersionRun_5268 {
  strings:
    $key_5268 = { 01 07 [2] 25 09 [2] 0e 25 [2] 20 07 [2] 34 1c [2] 3b 06 [2] 25 1b [2] 27 1a [2] 3c 1c [2] 20 1b [2] 3c 34 }

  condition:
    any of them
}