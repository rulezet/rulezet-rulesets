rule TTP_XOR_QUAD_CurrentVersionRun_4e54 {
  strings:
    $key_4e54 = { 1d 3b [2] 39 35 [2] 12 19 [2] 3c 3b [2] 28 20 [2] 27 3a [2] 39 27 [2] 3b 26 [2] 20 20 [2] 3c 27 [2] 20 08 }

  condition:
    any of them
}