rule TTP_XOR_QUAD_CurrentVersionRun_4968 {
  strings:
    $key_4968 = { 1a 07 [2] 3e 09 [2] 15 25 [2] 3b 07 [2] 2f 1c [2] 20 06 [2] 3e 1b [2] 3c 1a [2] 27 1c [2] 3b 1b [2] 27 34 }

  condition:
    any of them
}