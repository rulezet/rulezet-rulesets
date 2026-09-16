rule TTP_XOR_QUAD_CurrentVersionRun_7a08 {
  strings:
    $key_7a08 = { 29 67 [2] 0d 69 [2] 26 45 [2] 08 67 [2] 1c 7c [2] 13 66 [2] 0d 7b [2] 0f 7a [2] 14 7c [2] 08 7b [2] 14 54 }

  condition:
    any of them
}