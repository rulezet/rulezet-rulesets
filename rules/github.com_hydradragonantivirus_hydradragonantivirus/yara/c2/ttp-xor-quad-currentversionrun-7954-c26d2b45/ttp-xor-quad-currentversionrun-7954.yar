rule TTP_XOR_QUAD_CurrentVersionRun_7954 {
  strings:
    $key_7954 = { 2a 3b [2] 0e 35 [2] 25 19 [2] 0b 3b [2] 1f 20 [2] 10 3a [2] 0e 27 [2] 0c 26 [2] 17 20 [2] 0b 27 [2] 17 08 }

  condition:
    any of them
}