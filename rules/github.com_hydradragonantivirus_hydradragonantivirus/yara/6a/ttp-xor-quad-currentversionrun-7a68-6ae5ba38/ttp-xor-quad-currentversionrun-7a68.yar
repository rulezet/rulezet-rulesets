rule TTP_XOR_QUAD_CurrentVersionRun_7a68 {
  strings:
    $key_7a68 = { 29 07 [2] 0d 09 [2] 26 25 [2] 08 07 [2] 1c 1c [2] 13 06 [2] 0d 1b [2] 0f 1a [2] 14 1c [2] 08 1b [2] 14 34 }

  condition:
    any of them
}