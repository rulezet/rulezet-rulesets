rule TTP_XOR_QUAD_CurrentVersionRun_7a54 {
  strings:
    $key_7a54 = { 29 3b [2] 0d 35 [2] 26 19 [2] 08 3b [2] 1c 20 [2] 13 3a [2] 0d 27 [2] 0f 26 [2] 14 20 [2] 08 27 [2] 14 08 }

  condition:
    any of them
}