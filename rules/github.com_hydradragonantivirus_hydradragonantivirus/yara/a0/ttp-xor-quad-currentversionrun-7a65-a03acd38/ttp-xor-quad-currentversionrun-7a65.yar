rule TTP_XOR_QUAD_CurrentVersionRun_7a65 {
  strings:
    $key_7a65 = { 29 0a [2] 0d 04 [2] 26 28 [2] 08 0a [2] 1c 11 [2] 13 0b [2] 0d 16 [2] 0f 17 [2] 14 11 [2] 08 16 [2] 14 39 }

  condition:
    any of them
}