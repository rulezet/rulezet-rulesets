rule TTP_XOR_QUAD_CurrentVersionRun_5164 {
  strings:
    $key_5164 = { 02 0b [2] 26 05 [2] 0d 29 [2] 23 0b [2] 37 10 [2] 38 0a [2] 26 17 [2] 24 16 [2] 3f 10 [2] 23 17 [2] 3f 38 }

  condition:
    any of them
}