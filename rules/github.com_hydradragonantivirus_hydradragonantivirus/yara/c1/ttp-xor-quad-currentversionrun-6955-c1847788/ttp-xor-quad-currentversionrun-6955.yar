rule TTP_XOR_QUAD_CurrentVersionRun_6955 {
  strings:
    $key_6955 = { 3a 3a [2] 1e 34 [2] 35 18 [2] 1b 3a [2] 0f 21 [2] 00 3b [2] 1e 26 [2] 1c 27 [2] 07 21 [2] 1b 26 [2] 07 09 }

  condition:
    any of them
}