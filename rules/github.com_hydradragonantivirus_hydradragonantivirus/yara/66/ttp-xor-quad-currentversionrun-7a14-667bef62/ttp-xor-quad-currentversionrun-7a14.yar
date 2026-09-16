rule TTP_XOR_QUAD_CurrentVersionRun_7a14 {
  strings:
    $key_7a14 = { 29 7b [2] 0d 75 [2] 26 59 [2] 08 7b [2] 1c 60 [2] 13 7a [2] 0d 67 [2] 0f 66 [2] 14 60 [2] 08 67 [2] 14 48 }

  condition:
    any of them
}