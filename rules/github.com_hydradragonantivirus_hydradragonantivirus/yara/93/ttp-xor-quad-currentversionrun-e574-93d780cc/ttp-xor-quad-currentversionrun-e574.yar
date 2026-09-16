rule TTP_XOR_QUAD_CurrentVersionRun_e574 {
  strings:
    $key_e574 = { b6 1b [2] 92 15 [2] b9 39 [2] 97 1b [2] 83 00 [2] 8c 1a [2] 92 07 [2] 90 06 [2] 8b 00 [2] 97 07 [2] 8b 28 }

  condition:
    any of them
}