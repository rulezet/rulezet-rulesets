rule TTP_XOR_QUAD_CurrentVersionRun_3e54 {
  strings:
    $key_3e54 = { 6d 3b [2] 49 35 [2] 62 19 [2] 4c 3b [2] 58 20 [2] 57 3a [2] 49 27 [2] 4b 26 [2] 50 20 [2] 4c 27 [2] 50 08 }

  condition:
    any of them
}