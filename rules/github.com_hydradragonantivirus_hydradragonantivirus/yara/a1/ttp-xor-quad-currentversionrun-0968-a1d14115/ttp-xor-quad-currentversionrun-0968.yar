rule TTP_XOR_QUAD_CurrentVersionRun_0968 {
  strings:
    $key_0968 = { 5a 07 [2] 7e 09 [2] 55 25 [2] 7b 07 [2] 6f 1c [2] 60 06 [2] 7e 1b [2] 7c 1a [2] 67 1c [2] 7b 1b [2] 67 34 }

  condition:
    any of them
}