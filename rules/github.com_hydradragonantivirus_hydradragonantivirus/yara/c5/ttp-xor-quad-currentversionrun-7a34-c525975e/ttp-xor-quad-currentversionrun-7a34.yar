rule TTP_XOR_QUAD_CurrentVersionRun_7a34 {
  strings:
    $key_7a34 = { 29 5b [2] 0d 55 [2] 26 79 [2] 08 5b [2] 1c 40 [2] 13 5a [2] 0d 47 [2] 0f 46 [2] 14 40 [2] 08 47 [2] 14 68 }

  condition:
    any of them
}