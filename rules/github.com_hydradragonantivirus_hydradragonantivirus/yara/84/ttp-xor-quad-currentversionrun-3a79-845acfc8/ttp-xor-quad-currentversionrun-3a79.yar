rule TTP_XOR_QUAD_CurrentVersionRun_3a79 {
  strings:
    $key_3a79 = { 69 16 [2] 4d 18 [2] 66 34 [2] 48 16 [2] 5c 0d [2] 53 17 [2] 4d 0a [2] 4f 0b [2] 54 0d [2] 48 0a [2] 54 25 }

  condition:
    any of them
}