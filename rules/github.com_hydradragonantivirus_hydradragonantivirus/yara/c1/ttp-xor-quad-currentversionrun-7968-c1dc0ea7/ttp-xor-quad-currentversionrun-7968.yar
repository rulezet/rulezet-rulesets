rule TTP_XOR_QUAD_CurrentVersionRun_7968 {
  strings:
    $key_7968 = { 2a 07 [2] 0e 09 [2] 25 25 [2] 0b 07 [2] 1f 1c [2] 10 06 [2] 0e 1b [2] 0c 1a [2] 17 1c [2] 0b 1b [2] 17 34 }

  condition:
    any of them
}