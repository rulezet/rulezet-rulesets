rule TTP_XOR_QUAD_CurrentVersionRun_0c68 {
  strings:
    $key_0c68 = { 5f 07 [2] 7b 09 [2] 50 25 [2] 7e 07 [2] 6a 1c [2] 65 06 [2] 7b 1b [2] 79 1a [2] 62 1c [2] 7e 1b [2] 62 34 }

  condition:
    any of them
}