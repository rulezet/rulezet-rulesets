rule TTP_XOR_QUAD_CurrentVersionRun_7a09 {
  strings:
    $key_7a09 = { 29 66 [2] 0d 68 [2] 26 44 [2] 08 66 [2] 1c 7d [2] 13 67 [2] 0d 7a [2] 0f 7b [2] 14 7d [2] 08 7a [2] 14 55 }

  condition:
    any of them
}