rule TTP_XOR_QUAD_CurrentVersionRun_2368 {
  strings:
    $key_2368 = { 70 07 [2] 54 09 [2] 7f 25 [2] 51 07 [2] 45 1c [2] 4a 06 [2] 54 1b [2] 56 1a [2] 4d 1c [2] 51 1b [2] 4d 34 }

  condition:
    any of them
}