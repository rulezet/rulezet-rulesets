rule TTP_XOR_QUAD_CurrentVersionRun_7a45 {
  strings:
    $key_7a45 = { 29 2a [2] 0d 24 [2] 26 08 [2] 08 2a [2] 1c 31 [2] 13 2b [2] 0d 36 [2] 0f 37 [2] 14 31 [2] 08 36 [2] 14 19 }

  condition:
    any of them
}