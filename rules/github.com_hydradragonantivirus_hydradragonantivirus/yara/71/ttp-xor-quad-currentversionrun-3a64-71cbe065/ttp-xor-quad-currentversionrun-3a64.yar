rule TTP_XOR_QUAD_CurrentVersionRun_3a64 {
  strings:
    $key_3a64 = { 69 0b [2] 4d 05 [2] 66 29 [2] 48 0b [2] 5c 10 [2] 53 0a [2] 4d 17 [2] 4f 16 [2] 54 10 [2] 48 17 [2] 54 38 }

  condition:
    any of them
}