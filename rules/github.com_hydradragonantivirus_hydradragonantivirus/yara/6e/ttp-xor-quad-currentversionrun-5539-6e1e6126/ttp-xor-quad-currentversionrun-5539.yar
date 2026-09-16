rule TTP_XOR_QUAD_CurrentVersionRun_5539 {
  strings:
    $key_5539 = { 06 56 [2] 22 58 [2] 09 74 [2] 27 56 [2] 33 4d [2] 3c 57 [2] 22 4a [2] 20 4b [2] 3b 4d [2] 27 4a [2] 3b 65 }

  condition:
    any of them
}