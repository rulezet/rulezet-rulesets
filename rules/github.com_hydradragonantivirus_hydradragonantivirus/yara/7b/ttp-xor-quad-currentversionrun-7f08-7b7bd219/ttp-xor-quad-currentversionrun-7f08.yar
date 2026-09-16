rule TTP_XOR_QUAD_CurrentVersionRun_7f08 {
  strings:
    $key_7f08 = { 2c 67 [2] 08 69 [2] 23 45 [2] 0d 67 [2] 19 7c [2] 16 66 [2] 08 7b [2] 0a 7a [2] 11 7c [2] 0d 7b [2] 11 54 }

  condition:
    any of them
}