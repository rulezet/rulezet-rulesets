rule TTP_XOR_QUAD_CurrentVersionRun_7a79 {
  strings:
    $key_7a79 = { 29 16 [2] 0d 18 [2] 26 34 [2] 08 16 [2] 1c 0d [2] 13 17 [2] 0d 0a [2] 0f 0b [2] 14 0d [2] 08 0a [2] 14 25 }

  condition:
    any of them
}