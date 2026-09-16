rule TTP_XOR_QUAD_CurrentVersionRun_4977 {
  strings:
    $key_4977 = { 1a 18 [2] 3e 16 [2] 15 3a [2] 3b 18 [2] 2f 03 [2] 20 19 [2] 3e 04 [2] 3c 05 [2] 27 03 [2] 3b 04 [2] 27 2b }

  condition:
    any of them
}