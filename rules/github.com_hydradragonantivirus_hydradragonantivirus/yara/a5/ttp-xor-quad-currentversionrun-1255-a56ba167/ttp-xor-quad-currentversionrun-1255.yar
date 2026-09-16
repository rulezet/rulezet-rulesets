rule TTP_XOR_QUAD_CurrentVersionRun_1255 {
  strings:
    $key_1255 = { 41 3a [2] 65 34 [2] 4e 18 [2] 60 3a [2] 74 21 [2] 7b 3b [2] 65 26 [2] 67 27 [2] 7c 21 [2] 60 26 [2] 7c 09 }

  condition:
    any of them
}