rule TTP_XOR_QUAD_CurrentVersionRun_7a78 {
  strings:
    $key_7a78 = { 29 17 [2] 0d 19 [2] 26 35 [2] 08 17 [2] 1c 0c [2] 13 16 [2] 0d 0b [2] 0f 0a [2] 14 0c [2] 08 0b [2] 14 24 }

  condition:
    any of them
}