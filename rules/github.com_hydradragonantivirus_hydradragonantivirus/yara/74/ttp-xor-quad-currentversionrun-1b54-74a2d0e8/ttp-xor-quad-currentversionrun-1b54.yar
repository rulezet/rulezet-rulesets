rule TTP_XOR_QUAD_CurrentVersionRun_1b54 {
  strings:
    $key_1b54 = { 48 3b [2] 6c 35 [2] 47 19 [2] 69 3b [2] 7d 20 [2] 72 3a [2] 6c 27 [2] 6e 26 [2] 75 20 [2] 69 27 [2] 75 08 }

  condition:
    any of them
}