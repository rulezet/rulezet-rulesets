rule TTP_XOR_QUAD_CurrentVersionRun_6508 {
  strings:
    $key_6508 = { 36 67 [2] 12 69 [2] 39 45 [2] 17 67 [2] 03 7c [2] 0c 66 [2] 12 7b [2] 10 7a [2] 0b 7c [2] 17 7b [2] 0b 54 }

  condition:
    any of them
}